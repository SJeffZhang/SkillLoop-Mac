"""Loopback SGLang client and exact local chat-template token preflight."""

from __future__ import annotations

import json
import base64
import http.client
import os
import hashlib
import socket
import struct
import select
import subprocess
import threading
import time
import uuid
import stat
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from skillloop.protocol import decode_json
from skillloop.runtime.model_http import ModelHTTPIncomplete, request_model


MODEL_ID = "Qwen/Qwen3.8-27B-FP8"

_TOKENIZER_WORKER_CODE = """
import json,sys
from transformers import AutoTokenizer
tokenizer=AutoTokenizer.from_pretrained('/model',local_files_only=True,trust_remote_code=True)
for line in sys.stdin:
    payload=json.loads(line)
    try:
        if payload['operation']=='text':
            count=len(tokenizer.encode(payload['text'],add_special_tokens=False))
        else:
            messages=payload['messages']
            for message in messages:
                for call in message.get('tool_calls') or []:
                    function=call.get('function',call)
                    if isinstance(function.get('arguments'),str):
                        function['arguments']=json.loads(function['arguments'])
            ids=tokenizer.apply_chat_template(messages,tools=payload['tools'],tokenize=True,
                add_generation_prompt=True,enable_thinking=payload['enable_thinking'])
            count=len(ids['input_ids']) if hasattr(ids,'keys') else len(ids)
        result={'id':payload['id'],'count':count}
    except Exception:
        result={'id':payload['id'],'error':'tokenizer_invalid_input'}
    print(json.dumps(result),flush=True)
"""


class GatewayError(RuntimeError):
    def __init__(self, code: str, response: dict[str, Any] | None = None):
        super().__init__(code)
        self.response = response


class ExactDockerTokenizer:
    """Gateway-owned tokenizer. Prompts enter docker exec via stdin, never argv."""

    def __init__(self, container: str = "skillloop-m4-sglang"):
        self.container = container
        self._text_counts: dict[str, int] = {}
        self._process = None
        self._sequence = 0
        self._lock = threading.Lock()

    def _request(self, payload: dict[str, Any]) -> int:
        # One tokenizer process per owner. It holds no model KV cache and is
        # never reused by a different Runtime, scanner or evaluation role.
        with self._lock:
            if self._process is None:
                self._process = subprocess.Popen(
                    ["docker", "exec", "-i", self.container, "python3", "-u", "-c", _TOKENIZER_WORKER_CODE],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                )
                os.set_blocking(self._process.stdin.fileno(), False)
            self._sequence += 1
            payload = {**payload, "id": self._sequence}
            try:
                deadline = time.monotonic() + 30
                encoded = json.dumps(payload, ensure_ascii=False).encode() + b"\n"
                if len(encoded) > 8 * 1024 * 1024:
                    raise GatewayError("tokenizer_input_limit")
                offset = 0
                while offset < len(encoded):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([], [self._process.stdin], [], remaining)[1]:
                        raise GatewayError("tokenizer_unavailable")
                    offset += os.write(self._process.stdin.fileno(), encoded[offset:])
                response = bytearray()
                while b"\n" not in response:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([self._process.stdout], [], [], remaining)[0]:
                        raise GatewayError("tokenizer_unavailable")
                    chunk = os.read(self._process.stdout.fileno(), 4096)
                    if not chunk or len(response) + len(chunk) > 4096:
                        raise GatewayError("tokenizer_invalid_count")
                    response.extend(chunk)
                parsed = decode_json(bytes(response).strip())
                if (type(parsed) is not dict or parsed.get("id") != self._sequence or
                        type(parsed.get("count")) is not int or parsed["count"] < 0):
                    raise GatewayError("tokenizer_invalid_count")
                return parsed["count"]
            except (OSError, ValueError, GatewayError) as error:
                self.close()
                if isinstance(error, GatewayError):
                    raise
                raise GatewayError("tokenizer_unavailable") from error

    def close(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        if process.stdin:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        if process.stdout:
            process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def __del__(self):
        if getattr(self, "_process", None) is not None:
            self.close()

    def count(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
              *, enable_thinking: bool = True) -> int:
        return self._request({"operation": "chat", "messages": messages, "tools": tools,
                              "enable_thinking": enable_thinking})

    def count_text(self, text: str) -> int:
        # Process-local exact-string memoization; never shared between roles.
        # The deployment fixes tokenizer bytes for the lifetime of this object.
        if text in self._text_counts:
            return self._text_counts[text]
        count = self._request({"operation": "text", "text": text})
        self._text_counts[text] = count
        return count


def verify_tokenizer_snapshot(model_path, expected_hashes):
    """Check the complete bounded snapshot before loading tokenizer code/data."""
    from skillloop.protocol import digest_bytes
    root = Path(model_path)
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or type(expected_hashes) is not dict or not 1 <= len(expected_hashes) <= 32
            or not {'tokenizer.json', 'tokenizer_config.json'} <= set(expected_hashes)):
        raise GatewayError('tokenizer_frozen_snapshot_required')
    for name, digest in expected_hashes.items():
        if (type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]+', name)
                or name in {'.','..'} or name.endswith('.py')
                or type(digest) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',digest)):
            raise GatewayError('tokenizer_snapshot_pin_invalid')
    names=set()
    with os.scandir(root) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names)>32:
                raise GatewayError('tokenizer_snapshot_inventory_capacity')
    if names != set(expected_hashes):
        raise GatewayError('tokenizer_snapshot_inventory_changed')
    total = 0
    for name, digest in expected_hashes.items():
        fd = os.open(root/name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info = os.fstat(stream.fileno())
            total += info.st_size
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size > 67108864
                    or total > 134217728 or info.st_mode & 0o022):
                raise GatewayError('tokenizer_snapshot_file_invalid')
            raw = stream.read(info.st_size+1)
            if len(raw) != info.st_size or digest_bytes(raw) != digest:
                raise GatewayError('tokenizer_snapshot_bytes_changed')
    return dict(expected_hashes)


class ExactLocalTokenizer:
    """Offline tokenizer for a pinned local model snapshot inside the Linux VM."""

    def __init__(self, model_path: str, *, expected_hashes=None):
        if not os.path.isdir(model_path):
            raise GatewayError("tokenizer_snapshot_missing")
        self.snapshot_hashes = (verify_tokenizer_snapshot(model_path, expected_hashes)
                                if expected_hashes is not None else None)
        self.model_path = model_path
        from transformers import AutoTokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_path, local_files_only=True, trust_remote_code=expected_hashes is None)
        self._text_counts: dict[str, int] = {}
        from .ollama_bpe import OllamaPinnedBPE
        self._native_bpe = OllamaPinnedBPE(model_path)

    def count(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
              *, enable_thinking: bool = False) -> int:
        # Ollama's tool calls are represented by the same Qwen template data,
        # with OpenAI-style string arguments normalized before tokenization.
        messages = json.loads(json.dumps(messages, ensure_ascii=False))
        for message in messages:
            for call in message.get("tool_calls") or []:
                function = call.get("function", call)
                if isinstance(function.get("arguments"), str):
                    function["arguments"] = json.loads(function["arguments"])
                # The native Qwen renderer uses compact Go JSON here.
                for name, value in function.get("arguments", {}).items():
                    if isinstance(value, (dict, list)):
                        rendered = json.dumps(value, ensure_ascii=False,
                            sort_keys=True, separators=(",", ":"), allow_nan=False)
                        for character, escaped in (("&", "\\u0026"), ("<", "\\u003c"),
                                                   (">", "\\u003e"), ("\u2028", "\\u2028"),
                                                   ("\u2029", "\\u2029")):
                            rendered = rendered.replace(character, escaped)
                        function["arguments"][name] = rendered
        native_bpe = getattr(self, "_native_bpe", None)
        rendered = self._tokenizer.apply_chat_template(
            messages, tools=self.ollama_tools(tools), tokenize=native_bpe is None,
            add_generation_prompt=True, enable_thinking=enable_thinking)
        if native_bpe is not None:
            return native_bpe.count(rendered)
        return len(rendered["input_ids"]) if hasattr(rendered, "keys") else len(rendered)

    @staticmethod
    def ollama_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Mirror pinned Ollama 0.33.3 api/types.go JSON field order.

        Unsupported schema keywords are dropped by the provider. The Proxy
        still enforces the original schema; this mirrors only model rendering.
        """
        def property_schema(value):
            result = {}
            for key in ("anyOf", "type", "items", "description", "enum", "properties", "required"):
                item = value.get(key)
                if not item:
                    continue
                if key == "anyOf":
                    item = [property_schema(row) for row in item]
                elif key == "properties":
                    item = {name: property_schema(row) for name, row in item.items()}
                elif key == "type" and isinstance(item, list) and len(item) == 1:
                    item = item[0]
                result[key] = item
            return result

        normalized = []
        for tool in tools:
            function = tool["function"]
            source = function.get("parameters", {})
            parameters = {"type": source.get("type", "")}
            for key in ("$defs", "items", "required"):
                if source.get(key):
                    parameters[key] = source[key]
            properties = source.get("properties")
            parameters["properties"] = ({name: property_schema(row) for name, row in properties.items()}
                                         if properties is not None else None)
            body = {"name": function["name"]}
            if function.get("description"):
                body["description"] = function["description"]
            body["parameters"] = parameters
            normalized.append({"type": tool.get("type", ""),
                               **({"items": tool["items"]} if tool.get("items") else {}),
                               "function": body})
        return normalized

    def count_text(self, text: str) -> int:
        if text not in self._text_counts:
            self._text_counts[text] = self._native_bpe.count(text)
        return self._text_counts[text]

    def close(self) -> None:
        self._text_counts.clear()


class SGLangGateway:
    def __init__(self, endpoint: str, tokenizer: ExactDockerTokenizer,
                 *, max_context_tokens: int = 16_384, max_output_tokens: int = 2_048,
                 timeout_seconds: float = 180, backend_template_overhead_tokens: int = 66,
                 enable_thinking: bool = True):
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise GatewayError("loopback_endpoint_required")
        self.endpoint = endpoint.rstrip("/")
        self.tokenizer = tokenizer
        self.max_context_tokens = max_context_tokens
        self.max_output_tokens = max_output_tokens
        self.timeout_seconds = timeout_seconds
        # Calibrated against SGLang 0.5.19's returned prompt_tokens for the
        # fixed Qwen image/template and tool parser; mismatch fails closed.
        self.backend_template_overhead_tokens = backend_template_overhead_tokens
        self.enable_thinking = enable_thinking

    def count_final(self, text: str) -> int:
        return self.tokenizer.count_text(text)

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
                 *, remaining_seconds: float) -> tuple[dict[str, Any], int, float]:
        preflight_started = time.monotonic()
        prompt_tokens = self.tokenizer.count(messages, tools,
            enable_thinking=self.enable_thinking) + self.backend_template_overhead_tokens
        remaining_seconds -= time.monotonic() - preflight_started
        if prompt_tokens + self.max_output_tokens > self.max_context_tokens:
            raise GatewayError("context_exceeded")
        if remaining_seconds <= 0:
            raise GatewayError("run_deadline")
        payload = {"model": MODEL_ID, "messages": messages, "tools": tools,
                   "tool_choice": "auto", "temperature": 1.0, "top_p": 0.95,
                   "max_tokens": self.max_output_tokens}
        if not self.enable_thinking:
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        body = json.dumps(payload, ensure_ascii=False).encode()
        started = time.monotonic()
        try:
            status, raw = request_model(self.endpoint, '/v1/chat/completions', body,
                timeout=min(self.timeout_seconds, remaining_seconds))
        except ModelHTTPIncomplete as exc:
            raise GatewayError('provider_timeout', response={'http_status': exc.status,
                'body_read_incomplete': True,
                'raw_response_b64': base64.b64encode(exc.partial[:4194304]).decode('ascii'),
                'raw_response_truncated': len(exc.partial) > 4194304}) from exc
        except (OSError, http.client.HTTPException) as exc:
            raise GatewayError("provider_timeout") from exc
        if status != 200 or len(raw) > 4194304:
            raise GatewayError('provider_response_invalid', response={
                'http_status': status, 'raw_response_b64': base64.b64encode(raw[:4194304]).decode('ascii'),
                'raw_response_truncated': len(raw) > 4194304})
        try:
            parsed = decode_json(raw)
        except (ValueError, UnicodeError) as exc:
            raise GatewayError('provider_response_not_json') from exc
        if type(parsed) is not dict or parsed.get("model") not in {MODEL_ID, "/model"}:
            raise GatewayError("model_identity_mismatch")
        usage = parsed.get("usage") or {}
        if usage.get("prompt_tokens") != prompt_tokens:
            raise GatewayError("tokenizer_mismatch", response=parsed)
        if type(usage.get("completion_tokens")) is not int or usage["completion_tokens"] > self.max_output_tokens:
            raise GatewayError("output_token_limit", response=parsed)
        if any(choice.get("finish_reason") == "length" for choice in parsed.get("choices", [])):
            raise GatewayError("output_token_limit", response=parsed)
        return parsed, prompt_tokens, time.monotonic() - started


class OllamaGateway:
    """Native Ollama chat adapter with a deployment-specific token calibration.

    The tokenizer counts the pinned model's chat template. A calibration offset
    must be measured against Ollama's prompt_eval_count before formal runs.
    Every response checks that calibration again and fails closed on drift.
    """

    def __init__(self, endpoint: str, tokenizer: ExactDockerTokenizer, *,
                 model: str = "qwen3.8:27b-mxfp8", template_overhead_tokens: int | None = None,
                 max_context_tokens: int = 16_384, max_output_tokens: int = 2_048,
                 timeout_seconds: float = 180, unix_socket_path: str | None = None,
                 expected_server_uid: int | None = None, temperature: float = 1.0, top_p: float = 0.95):
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {
                "127.0.0.1", "localhost", "host.docker.internal"}:
            raise GatewayError("local_endpoint_required")
        if not model or not model.startswith("qwen3.8:"):
            raise GatewayError("model_identity_invalid")
        self.endpoint = endpoint.rstrip("/")
        self.tokenizer = tokenizer
        self.model = model
        self.template_overhead_tokens = template_overhead_tokens
        self.max_context_tokens = max_context_tokens
        self.max_output_tokens = max_output_tokens
        self.timeout_seconds = timeout_seconds
        self.unix_socket_path = unix_socket_path
        if expected_server_uid is not None and (type(expected_server_uid) is not int or expected_server_uid != 21011 or unix_socket_path is None):
            raise GatewayError('native_gateway_frozen_peer_required')
        if (type(temperature) not in (int,float) or not 0<=temperature<=2
                or type(top_p) not in (int,float) or not 0<top_p<=1):
            raise GatewayError('native_gateway_sampling_invalid')
        self.expected_server_uid=expected_server_uid
        self.temperature,self.top_p=temperature,top_p

    def count_final(self, text: str) -> int:
        return self.tokenizer.count_text(text)

    @staticmethod
    def _ollama_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        converted = []
        tool_names = {}
        for message in messages:
            item = dict(message)
            if item["role"] == "assistant" and item.get("tool_calls"):
                calls = []
                for call in item["tool_calls"]:
                    function = dict(call["function"])
                    if isinstance(function.get("arguments"), str):
                        function["arguments"] = json.loads(function["arguments"])
                    tool_names[call["id"]] = function["name"]
                    calls.append({"function": function})
                item["tool_calls"] = calls
            elif item["role"] == "tool":
                call_id = item.pop("tool_call_id", None)
                if call_id not in tool_names:
                    raise GatewayError("tool_call_identity_missing")
                item["tool_name"] = tool_names[call_id]
            converted.append(item)
        return converted

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
                 *, remaining_seconds: float, inference_context=None) -> tuple[dict[str, Any], int, float]:
        if self.template_overhead_tokens is None:
            raise GatewayError("ollama_token_calibration_required")
        started = time.monotonic()
        prompt_tokens = self.tokenizer.count(messages, tools,
            enable_thinking=False) + self.template_overhead_tokens
        if prompt_tokens < 0 or prompt_tokens + self.max_output_tokens > self.max_context_tokens:
            raise GatewayError("context_exceeded")
        remaining_seconds -= time.monotonic() - started
        if remaining_seconds <= 0:
            raise GatewayError("run_deadline")
        payload = {"model": self.model, "messages": self._ollama_messages(messages),
                   "tools": tools, "stream": False, "think": False,
                   "options": {"temperature": self.temperature, "top_p": self.top_p,
                               "num_ctx": self.max_context_tokens,
                               "num_predict": self.max_output_tokens}}
        if self.expected_server_uid == 21011 and os.geteuid() in {21002,21006,21007}:
            if type(inference_context) is not dict:
                raise GatewayError("runtime_inference_current_identity_required")
            payload["skillloop_runtime_context"] = inference_context
        elif inference_context is not None:
            raise GatewayError("runtime_inference_context_wrong_role")
        body = json.dumps(payload, ensure_ascii=False).encode()
        model_started = time.monotonic()
        def parse_native(raw,status):
            diagnostic={'http_status':status,
                'raw_response_b64':base64.b64encode(raw[:4194304]).decode('ascii'),
                'raw_response_truncated':len(raw)>4194304}
            if status!=200 or len(raw)>4194304:
                if status==502 and len(raw)<=4194304:
                    try:failure=decode_json(raw)
                    except (ValueError,UnicodeError):failure=None
                    if (type(failure) is dict and failure.get('kind')=='LocalModelTransportFailure'
                            and failure.get('body_read_incomplete') is True):
                        diagnostic['body_read_incomplete']=True
                        raise GatewayError('provider_timeout',response=diagnostic)
                raise GatewayError('provider_response_invalid',response=diagnostic)
            try:return decode_json(raw)
            except (ValueError,UnicodeError) as error:
                raise GatewayError('provider_response_not_json',response=diagnostic) from error
        def validate_peer(sock):
            if self.expected_server_uid is not None:
                if not hasattr(socket, 'SO_PEERCRED'):
                    raise GatewayError('native_gateway_kernel_peer_unavailable')
                peer = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
                if struct.unpack('3i', peer)[1] != self.expected_server_uid:
                    raise GatewayError('native_gateway_peer_denied')
        try:
            status, raw = request_model(self.endpoint, '/api/chat', body,
                timeout=min(self.timeout_seconds, remaining_seconds),
                unix_socket_path=self.unix_socket_path, peer_validator=validate_peer)
            parsed = parse_native(raw, status)
        except ModelHTTPIncomplete as exc:
            raise GatewayError('provider_timeout', response={'http_status': exc.status,
                'body_read_incomplete': True,
                'raw_response_b64': base64.b64encode(exc.partial[:4194304]).decode('ascii'),
                'raw_response_truncated': len(exc.partial) > 4194304}) from exc
        except (OSError, http.client.HTTPException) as exc:
            raise GatewayError("provider_timeout") from exc
        if type(parsed) is not dict or parsed.get("model") != self.model:
            raise GatewayError("model_identity_mismatch", response=parsed)
        if parsed.get('done') is not True or parsed.get("done_reason") != "stop":
            raise GatewayError("model_incomplete", response=parsed)
        if parsed.get("prompt_eval_count") != prompt_tokens:
            raise GatewayError("tokenizer_mismatch", response=parsed)
        output_tokens = parsed.get("eval_count")
        if type(output_tokens) is not int or output_tokens < 0 or output_tokens > self.max_output_tokens:
            raise GatewayError("output_token_limit", response=parsed)
        native = parsed.get("message")
        if type(native) is not dict or native.get("role") != "assistant":
            raise GatewayError("invalid_model_response", response=parsed)
        if native.get("thinking"):
            raise GatewayError("thinking_mode_mismatch", response=parsed)
        tool_calls = []
        for call in native.get("tool_calls") or []:
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                raise GatewayError("invalid_model_tool_call", response=parsed)
            tool_calls.append({"id": "call_" + uuid.uuid4().hex, "type": "function",
                "function": {"name": function["name"],
                             "arguments": json.dumps(function.get("arguments", {}), ensure_ascii=False)}})
        result = {"id": "chatcmpl_" + uuid.uuid4().hex, "model": self.model,
                  "choices": [{"index": 0, "message": {"role": "assistant",
                      "content": native.get("content") or "", "tool_calls": tool_calls},
                      "finish_reason": "tool_calls" if tool_calls else "stop"}],
                  "usage": {"prompt_tokens": prompt_tokens,
                            "completion_tokens": output_tokens,
                            "total_tokens": prompt_tokens + output_tokens,
                            "reasoning_tokens": 0},
                  "backend_response": parsed,
                  "backend_response_raw_b64": base64.b64encode(raw).decode("ascii"),
                  "backend_response_bytes_digest": "sha256:"+hashlib.sha256(raw).hexdigest()}
        return result, prompt_tokens, time.monotonic() - model_started
