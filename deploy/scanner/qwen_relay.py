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
                 native_chat: bool = False, tokenizer=None):
        if model_host not in {"127.0.0.1", "localhost", "host.docker.internal"}:
            raise ValueError("model_endpoint_must_be_loopback")
        if backend not in {"sglang", "ollama"}:
            raise ValueError("unknown_model_backend")
        self.socket_path = Path(socket_path)
        self.model_host = model_host
        self.model_port = model_port
        self.model_id = model_id
        self.backend = backend
        if native_chat and backend != "ollama":
            raise ValueError("native_chat_requires_ollama")
        self.native_chat = native_chat
        self.tokenizer = tokenizer
        self.chat_requests = 0
        self.max_chat_requests = max_chat_requests
        self.usage_records = []
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    def __enter__(self):
        if self.socket_path.exists():
            raise FileExistsError(self.socket_path)
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _forward(self, method: str, body: bytes | None = None, expected_prompt_tokens=None):
                upstream = http.client.HTTPConnection(bridge.model_host, bridge.model_port,
                                                      timeout=600)
                try:
                    upstream.request(method, self.path, body=body,
                                     headers={"Content-Type": "application/json"})
                    response = upstream.getresponse()
                    payload = response.read(8_388_609)
                    if len(payload) > 8_388_608:
                        self.send_error(502, "model_response_too_large")
                        return
                    if method == "POST":
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
                                    "http_status": response.status, "token_mismatch": token_mismatch})
                            if token_mismatch:
                                self.send_error(502, "model_tokenizer_mismatch")
                                return
                        except (ValueError, AttributeError):
                            pass
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (OSError, TimeoutError, http.client.HTTPException):
                    self.send_error(502, "local_model_unavailable")
                finally:
                    upstream.close()

            def do_GET(self):
                if self.path != "/v1/models":
                    self.send_error(404)
                    return
                self._forward("GET")

            def do_POST(self):
                native = self.path == "/api/chat" and bridge.native_chat
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
                    if native:
                        # This route cannot pull, delete or reconfigure models.
                        # Fix all resource/sampling options at the trust boundary.
                        value = {"model": bridge.model_id, "messages": value["messages"],
                                 "tools": value.get("tools", []), "stream": False, "think": False,
                                 "options": {"temperature": 1.0, "top_p": 0.95,
                                             "num_ctx": 16384, "num_predict": 2048}}
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
                        if expected + 2048 > 16384:
                            raise ValueError("model_context_limit")
                    payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
                except (KeyError, TypeError, ValueError, UnicodeError):
                    self.send_error(400, "invalid_local_model_request")
                    return
                with bridge._lock:
                    if bridge.max_chat_requests is not None and bridge.chat_requests >= bridge.max_chat_requests:
                        self.send_error(429, "scanner_model_budget_exhausted")
                        return
                    bridge.chat_requests += 1
                self._forward("POST", payload, expected_prompt_tokens=expected)

        self._server = _ThreadedUnixServer(str(self.socket_path), Handler)
        os.chmod(self.socket_path, 0o600)
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
