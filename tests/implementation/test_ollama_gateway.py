"""Contract checks for the Mac Ollama response adapter."""

import json
import socket
import socketserver
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch

from deploy.scanner.qwen_relay import HostModelBridge
from skillloop.runtime.gateway import GatewayError, OllamaGateway


class _Tokenizer:
    def count(self, _messages, _tools, *, enable_thinking):
        assert enable_thinking is False
        return 100

    def count_text(self, text):
        return len(text)


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit):
        return json.dumps({"model": "qwen3.8:27b-mxfp8", "done_reason": "stop",
            "prompt_eval_count": 103,
            "eval_count": 12, "message": {"role": "assistant", "content": "",
            "tool_calls": [{"function": {"name": "read_resource",
                                         "arguments": {"resource_id": "notes"}}}]}}).encode()


class OllamaGatewayTest(unittest.TestCase):
    def setUp(self):
        self.gateway = OllamaGateway("http://127.0.0.1:11434", _Tokenizer(),
                                     template_overhead_tokens=3)

    def test_tool_call_and_usage_mapping(self):
        with patch("urllib.request.urlopen", return_value=_Response()) as opener:
            response, preflight, _latency = self.gateway.complete(
                [{"role": "user", "content": "read"}], [], remaining_seconds=30)
        payload = json.loads(opener.call_args.args[0].data)
        self.assertEqual(payload["think"], False)
        self.assertEqual(payload["stream"], False)
        self.assertEqual(preflight, 103)
        self.assertEqual(response["usage"]["total_tokens"], 115)
        self.assertEqual(json.loads(response["choices"][0]["message"]["tool_calls"][0]
                                    ["function"]["arguments"]), {"resource_id": "notes"})

    def test_calibration_is_required(self):
        gateway = OllamaGateway("http://127.0.0.1:11434", _Tokenizer())
        with self.assertRaisesRegex(GatewayError, "ollama_token_calibration_required"):
            gateway.complete([], [], remaining_seconds=30)

    def test_mismatch_fails_closed(self):
        self.gateway.template_overhead_tokens = 2
        with patch("urllib.request.urlopen", return_value=_Response()):
            with self.assertRaisesRegex(GatewayError, "tokenizer_mismatch"):
                self.gateway.complete([], [], remaining_seconds=30)

    def test_scanner_bridge_uses_ollama_thinking_control(self):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                observed.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = b'{"model":"qwen3.8:27b-mxfp8","usage":{}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True

        with Server(("127.0.0.1", 0), Handler) as upstream, tempfile.TemporaryDirectory() as tmp:
            with HostModelBridge(Path(tmp) / "model.sock", model_port=upstream.server_address[1],
                                 model_id="qwen3.8:27b-mxfp8", backend="ollama"):
                import threading
                thread = threading.Thread(target=upstream.serve_forever, daemon=True)
                thread.start()
                try:
                    body = json.dumps({"model": "qwen3.8:27b-mxfp8",
                                       "messages": [], "chat_template_kwargs": {"enable_thinking": True}}).encode()
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(str(Path(tmp) / "model.sock"))
                        client.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n"
                                       + b"Content-Type: application/json\r\nContent-Length: "
                                       + str(len(body)).encode() + b"\r\n\r\n" + body)
                        self.assertIn(b"200 OK", client.recv(4096))
                finally:
                    upstream.shutdown()
                    thread.join(timeout=5)
        self.assertEqual(observed[0]["reasoning_effort"], "none")
        self.assertNotIn("chat_template_kwargs", observed[0])


if __name__ == "__main__":
    unittest.main()
