"""Network-free scanner bridge: container loopback -> mounted UDS -> host loopback.

The host process permits only the configured local SGLang endpoint. The
SkillSpector container keeps Docker ``--network none`` and sees only its own
127.0.0.1 plus a mounted Unix socket. This is a byte relay, not an authority
boundary for model responses; scanner findings still need trusted validation.
"""

from __future__ import annotations

import os
import http.client
import json
import hashlib
import selectors
import socket
import socketserver
import threading
import struct
import stat
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path


def relay(left: socket.socket, right: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    try:
        while selector.get_map():
            for key, _ in selector.select(timeout=30):
                source = key.fileobj
                target = key.data
                data = source.recv(65536)
                if not data:
                    selector.unregister(source)
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                target.sendall(data)
    finally:
        selector.close()


class _ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class HostModelBridge:
    def __init__(self, socket_path: Path, *, model_host: str = "127.0.0.1",
                 model_port: int = 30000, max_chat_requests: int | None = None,
                 model_id: str = "Qwen/Qwen3.8-27B-FP8", backend: str = "sglang",
                 native_chat: bool = False, tokenizer=None, allowed_client_uid=None,
                 temperature=1.0, top_p=0.95, max_output_tokens=2048,
                 request_timeout_seconds=600, campaign_deadline=None, semantic_scope_digest=None, evidence_observer=None):
        if model_host not in {"127.0.0.1", "localhost", "host.docker.internal"}:
            raise ValueError("model_endpoint_must_be_loopback")
        if backend not in {"sglang", "ollama"}:
            raise ValueError("unknown_model_backend")
        self.semantic_scope_digest=semantic_scope_digest
        self.evidence_observer=evidence_observer
        if semantic_scope_digest is not None:
            import re
            if allowed_client_uid!=21011 or not re.fullmatch(r"sha256:[0-9a-f]{64}",semantic_scope_digest) or evidence_observer is None:
                raise ValueError("semantic_gateway_exact_scope_required")
        self.socket_path = Path(socket_path)
        self.model_host = model_host
        self.model_port = model_port
        self.model_id = model_id
        self.backend = backend
        if native_chat and backend != "ollama":
            raise ValueError("native_chat_requires_ollama")
        self.native_chat = native_chat
        self.tokenizer = tokenizer
        self.allowed_client_uid = allowed_client_uid
        if allowed_client_uid is not None:
            if (os.geteuid()!=21011 or not hasattr(socket,'SO_PEERCRED')
                    or allowed_client_uid not in ({21011} if semantic_scope_digest is not None else {21002,21006,21007})
                    or not native_chat or tokenizer is None
                    or not getattr(tokenizer,'snapshot_hashes',None)
                    or type(max_chat_requests) is not int or not 1<=max_chat_requests<=128
                    or type(request_timeout_seconds) is not int or not 1<=request_timeout_seconds<=180
                    or campaign_deadline is None):
                raise ValueError('formal_model_bridge_actual_identity_and_budget_required')
            deadline=datetime.fromisoformat(campaign_deadline.replace('Z','+00:00'))
            if deadline.tzinfo is None or not 0<(deadline-datetime.now(timezone.utc)).total_seconds()<=28800:
                raise ValueError('formal_model_bridge_original_deadline')
            expected={21002:(1.0,0.95,2048),21006:(0.7,0.9,512),
                      21007:(0.2,0.9,1024)}.get(allowed_client_uid)
            if expected is not None and (temperature,top_p,max_output_tokens)!=expected:
                raise ValueError('formal_model_bridge_frozen_sampling')
            self.deadline=deadline
        else:self.deadline=None
        self.temperature,self.top_p,self.max_output_tokens=temperature,top_p,max_output_tokens
        self.request_timeout_seconds=request_timeout_seconds
        self.chat_requests = 0
        self.max_chat_requests = max_chat_requests
        self.usage_records = []
        self._lock = threading.Lock()
        self._inference_lock = threading.Lock()
        self._server = None
        self._thread = None

    def __enter__(self):
        if os.path.lexists(self.socket_path):
            raise FileExistsError(self.socket_path)
        if self.allowed_client_uid is not None:
            parent=self.socket_path.parent.lstat()
            if (not self.socket_path.is_absolute() or self.socket_path.parent.is_symlink()
                    or parent.st_uid!=21011 or parent.st_gid!=self.allowed_client_uid
                    or stat.S_IMODE(parent.st_mode)!=0o750
                    or self.allowed_client_uid not in set(os.getgroups())|{os.getegid()}):
                raise PermissionError('formal_model_bridge_socket_directory_grant')
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _forward(self, method: str, body: bytes | None = None, expected_prompt_tokens=None):
                from skillloop.runtime.model_http import ModelHTTPIncomplete, request_model
                parsed = None
                try:
                    timeout = bridge.request_timeout_seconds
                    if bridge.deadline is not None:
                        timeout = min(timeout, (bridge.deadline - datetime.now(timezone.utc)).total_seconds())
                    if timeout <= 0:
                        raise TimeoutError('model_bridge_deadline')
                    status, payload = request_model(
                        f'http://{bridge.model_host}:{bridge.model_port}',
                        "/api/chat" if bridge.semantic_scope_digest is not None and method == "POST" else self.path,
                        body, timeout=timeout, method=method, maximum_bytes=8388608)
                    if len(payload) > 8_388_608:
                        if method == 'POST' and bridge.evidence_observer is not None:
                            bridge.evidence_observer('response_oversized', body, payload, status)
                        self.send_error(502, "model_response_too_large")
                        return
                    if method == "POST":
                        if bridge.evidence_observer is not None:
                            bridge.evidence_observer("response",body,payload,status)
                        try:
                            parsed = json.loads(payload)
                            if bridge.backend == "ollama" and parsed.get("model") != bridge.model_id:
                                self.send_error(502, "model_identity_mismatch")
                                return
                            usage = ({"prompt_tokens": parsed.get("prompt_eval_count"),
                                      "completion_tokens": parsed.get("eval_count")} if bridge.native_chat
                                     else parsed.get("usage", {}))
                            token_mismatch = expected_prompt_tokens is not None and usage.get("prompt_tokens") != expected_prompt_tokens
                            with bridge._lock:
                                bridge.usage_records.append({"usage": usage, "preflight_prompt_tokens": expected_prompt_tokens,
                                    "request_digest": "sha256:" + hashlib.sha256(body or b"").hexdigest(), "thinking": False,
                                    "http_status": status, "token_mismatch": token_mismatch})
                            if token_mismatch:
                                self.send_error(502, "model_tokenizer_mismatch")
                                return
                        except (ValueError, AttributeError):
                            pass
                    if bridge.semantic_scope_digest is not None and method=='POST' and status==200:
                        if (not isinstance(parsed,dict) or parsed.get('done') is not True or parsed.get('done_reason')!='stop'
                                or parsed.get('message',{}).get('thinking') or parsed.get('message',{}).get('tool_calls')
                                or type(parsed.get('eval_count')) is not int or not 0<=parsed['eval_count']<=bridge.max_output_tokens):
                            self.send_error(502,'semantic_model_terminal_incomplete');return
                        payload=json.dumps({'id':'semantic-local','object':'chat.completion','model':bridge.model_id,
                            'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':parsed['message']['content']}}],
                            'usage':{'prompt_tokens':parsed['prompt_eval_count'],'completion_tokens':parsed['eval_count'],
                                     'total_tokens':parsed['prompt_eval_count']+parsed['eval_count']}}).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except ModelHTTPIncomplete as error:
                    if method == 'POST' and bridge.evidence_observer is not None:
                        bridge.evidence_observer('response_incomplete', body, error.partial, error.status)
                    self.send_error(502, "local_model_unavailable")
                except (OSError, TimeoutError, http.client.HTTPException, KeyError, TypeError, ValueError):
                    self.send_error(502, "local_model_unavailable")

            def do_GET(self):
                if bridge.allowed_client_uid is not None:
                    self.send_error(404)
                    return
                if self.path != "/v1/models":
                    self.send_error(404)
                    return
                self._forward("GET")

            def do_POST(self):
                if bridge.deadline is not None and (bridge.deadline-datetime.now(timezone.utc)).total_seconds()<=bridge.request_timeout_seconds+60:
                    self.send_error(429,'original_model_budget_exhausted')
                    return
                self.connection.settimeout(bridge.request_timeout_seconds)
                native = (self.path == "/api/chat" or bridge.semantic_scope_digest is not None and self.path == "/v1/chat/completions") and bridge.native_chat
                if (bridge.native_chat and not native) or (self.path != "/v1/chat/completions" and not native):
                    self.send_error(404)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                    if size < 0 or size > 1_048_576:
                        raise ValueError("request_size")
                    data = self.rfile.read(size)
                    value = json.loads(data)
                    if type(value) is not dict or value.get("model") != bridge.model_id:
                        raise ValueError("model_identity")
                    if bridge.semantic_scope_digest is not None and value.get("tools"):
                        raise ValueError("semantic_analyzer_has_no_tools")
                    if native:
                        # This route cannot pull, delete or reconfigure models.
                        # Fix all resource/sampling options at the trust boundary.
                        value = {"model": bridge.model_id, "messages": value["messages"],
                                 "tools": value.get("tools", []), "stream": False, "think": False,
                                 "options": {"temperature": bridge.temperature, "top_p": bridge.top_p,
                                             "num_ctx": 16384, "num_predict": bridge.max_output_tokens}}
                    elif bridge.backend == "sglang":
                        value["chat_template_kwargs"] = {"enable_thinking": False}
                    else:
                        value.pop("chat_template_kwargs", None)
                        value["reasoning_effort"] = "none"
                        value["stream"] = False
                        value["temperature"] = 0.0
                        value["top_p"] = 0.95
                        value["max_tokens"] = min(int(value.get("max_tokens") or 2048), 2048)
                        if value["max_tokens"] <= 0:
                            raise ValueError("output_token_limit")
                    expected = None
                    if bridge.tokenizer is not None:
                        expected = bridge.tokenizer.count(value["messages"], value.get("tools", []), enable_thinking=False)
                        if expected + bridge.max_output_tokens > 16384:
                            raise ValueError("model_context_limit")
                    payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
                except (KeyError, TypeError, ValueError, UnicodeError):
                    self.send_error(400, "invalid_local_model_request")
                    return
                if not bridge._inference_lock.acquire(blocking=False):
                    self.send_error(429,'model_inference_already_active')
                    return
                try:
                    with bridge._lock:
                        if bridge.max_chat_requests is not None and bridge.chat_requests >= bridge.max_chat_requests:
                            self.send_error(429, "scanner_model_budget_exhausted")
                            return
                        bridge.chat_requests += 1
                    if bridge.evidence_observer is not None:bridge.evidence_observer("request",payload,None,None)
                    self._forward("POST", payload, expected_prompt_tokens=expected)
                finally:bridge._inference_lock.release()

        class Server(_ThreadedUnixServer):
            def verify_request(self, request, client_address):
                if bridge.allowed_client_uid is None:return True
                peer=struct.unpack('3i',request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                return peer[1]==bridge.allowed_client_uid
        self._server = Server(str(self.socket_path), Handler)
        if self.allowed_client_uid is None:os.chmod(self.socket_path, 0o600)
        else:
            os.chown(self.socket_path,-1,self.allowed_client_uid)
            os.chmod(self.socket_path,0o660)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def _count(self, count: int) -> None:
        with self._lock:
            self.chat_requests += count

    def __exit__(self, *_exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self.socket_path.unlink(missing_ok=True)


def run_guest_relay(socket_path: Path, *, port: int = 31000):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.connect(str(socket_path))
                relay(self.request, upstream)

    server = _ThreadedTCPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
