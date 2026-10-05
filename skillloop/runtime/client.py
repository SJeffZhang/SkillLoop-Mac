"""Authenticated local Proxy transport; Runtime never opens the SQLite file."""

from __future__ import annotations

import uuid
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from skillloop.protocol import canonical_json_line, decode_json, validate_envelope
from skillloop.proxy.wire import make_control, validate_control


class ProxyRPCError(RuntimeError):
    pass


class ProxyClient:
    def __init__(self, socket_dir: Path, *, timeout_seconds: float = 10, expected_server_uid: int | None = None):
        self.socket_dir = Path(socket_dir)
        self.timeout_seconds = timeout_seconds
        if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 0<timeout_seconds<=10:
            raise ValueError('proxy_original_transport_timeout')
        if expected_server_uid is not None and (type(expected_server_uid) is not int or expected_server_uid < 0):
            raise ValueError('proxy_server_identity_configuration')
        self.expected_server_uid = expected_server_uid

    def _send(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if name not in {"control.sock", "tool.sock", "ingress.sock", "admin.sock"}:
            raise ProxyRPCError("invalid_proxy_endpoint")
        encoded = canonical_json_line(payload)
        if len(encoded) > 262_144:
            raise ProxyRPCError("proxy_request_too_large")
        try:
            from skillloop.runtime.local_packet import exchange_packet
            allowance=self.timeout_seconds
            if payload.get('kind')=='ControlRequest':
                original=datetime.fromisoformat(payload['body']['deadline'].replace('Z','+00:00'))
                if original.tzinfo is None:raise ProxyRPCError('proxy_request_deadline')
                allowance=min(allowance,(original-datetime.now(timezone.utc)).total_seconds())
                if allowance<=0:raise ProxyRPCError('expired')
            raw=exchange_packet(self.socket_dir/name,encoded,timeout=allowance,
                expected_server_uid=self.expected_server_uid,maximum_bytes=262144)
        except PermissionError as exc:
            raise ProxyRPCError('proxy_server_identity_mismatch') from exc
        except OSError as exc:
            # A lost response cannot establish whether a durable effect committed.
            # Preserve the spent attempt; authoritative recovery precedes any retry.
            raise ProxyRPCError("proxy_transport_unknown") from exc
        try:
            value = decode_json(raw)
        except ValueError as exc:
            raise ProxyRPCError("invalid_proxy_response") from exc
        if type(value) is not dict or type(value.get("ok")) is not bool:
            raise ProxyRPCError("invalid_proxy_response")
        if value["ok"] is False:
            if (set(value) != {"ok", "error_code"} or
                    type(value["error_code"]) is not str or
                    not value["error_code"] or len(value["error_code"]) > 128):
                raise ProxyRPCError("invalid_proxy_error_response")
            raise ProxyRPCError(value["error_code"])
        expected = {"ok", "call_digest"} if name == "ingress.sock" else {"ok", "result"}
        if set(value) != expected:
            raise ProxyRPCError("invalid_proxy_success_response")
        return value

    def import_call(self, call: dict[str, Any]) -> str:
        validate_envelope(call)
        if call["kind"] != "ToolCall":
            raise ProxyRPCError("not_tool_call")
        reply = self._send("ingress.sock", call)
        if reply.get("call_digest") != call["digest"]:
            raise ProxyRPCError("call_identity_mismatch")
        return call["digest"]

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        deadline = datetime.now(timezone.utc) + timedelta(seconds=9)
        request = make_control("ControlRequest", {
            "operation_id": "runtime-" + uuid.uuid4().hex,
            "deadline": deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": method, "params": params,
        })
        result = self._send("tool.sock", request).get("result")
        if type(result) is not dict:
            raise ProxyRPCError("invalid_proxy_result")
        if result.get("kind") == "ToolResult":
            validate_envelope(result)
        else:
            validate_control(result)
        return result

    def control_request(self, method: str, params: dict[str, Any], *, operation_id: str,
                        admin: bool = False) -> dict[str, Any]:
        """Frozen control request with stable operation ID and real peer identity.

        The deadline bounds this transport attempt; authoritative methods bind
        replay to logical parameters. A lost reply never triggers an auto retry.
        """
        expected = 21010 if admin else 21001
        import os
        if os.geteuid() != expected or self.expected_server_uid != 21003:
            raise PermissionError("formal_control_transport_identity")
        request = make_control("ControlRequest", {
            "operation_id": operation_id,
            "deadline": (datetime.now(timezone.utc) + timedelta(seconds=9)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": method, "params": params})
        reply = self._send("admin.sock" if admin else "control.sock", request)
        result = reply["result"]
        if type(result) is not dict:
            raise ProxyRPCError("invalid_control_result")
        if result.get("kind") == "Lease":
            return validate_envelope(result)
        return validate_control(result)
