"""Linux AF_UNIX SOCK_SEQPACKET boundary with kernel peer UID authorization."""

from __future__ import annotations

import os
import selectors
import socket
import sqlite3
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from skillloop.protocol import ProtocolError, canonical_json_line, parse_envelope, digest_jcs

from .store import ProxyError, ProxyStore
from .wire import make_control, parse_control


MAX_MESSAGE_BYTES = 262_144
MAX_REQUEST_SECONDS = 10


def _deadline(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("deadline_timezone")
    return parsed.astimezone(timezone.utc)


class ProxyServer:
    """Two sockets: controller operations and registered runtime tool calls."""

    def __init__(self, store: ProxyStore, directory: Path, *,
                 controller_uid: int = 21001, runtime_uid: int = 21002,
                 socket_mode: int = 0o660, controller_gid: int | None = None,
                 runtime_gid: int | None = None, approval_authority=None,
                 admin_gid: int | None = None, on_cancel=None, inference_authority=None,
                 inference_directory: Path | None = None):
        if not hasattr(socket, "SO_PEERCRED") or not hasattr(socket, "SOCK_SEQPACKET"):
            raise RuntimeError("linux_peercred_seqpacket_required")
        if approval_authority is not None and (os.geteuid() != 21003 or
                approval_authority.store is not store or admin_gid != 21010 or
                controller_uid != 21001 or runtime_uid != 21002):
            raise PermissionError("formal_approval_server_identity")
        self.approval_authority = approval_authority
        self.admin_gid = admin_gid
        self.on_cancel = on_cancel
        self.inference_authority = inference_authority
        self.inference_directory = inference_directory
        if (inference_authority is None) != (inference_directory is None):
            raise ValueError("inference_authority_endpoint_pair")
        if inference_authority is not None:
            import stat
            from .inference_authority import RuntimeInferenceAuthority
            info = Path(inference_directory).lstat()
            if (type(inference_authority) is not RuntimeInferenceAuthority or inference_authority.store is not store
                    or os.geteuid() != 21003 or not Path(inference_directory).is_absolute()
                    or Path(inference_directory).is_symlink() or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 21003 or info.st_gid != 21011 or stat.S_IMODE(info.st_mode) != 0o750):
                raise PermissionError("inference_authority_endpoint_custody")
        self.store = store
        self.directory = Path(directory)
        self.controller_uid = controller_uid
        self.runtime_uid = runtime_uid
        self.socket_mode = socket_mode
        self.controller_gid = controller_gid
        self.runtime_gid = runtime_gid
        self._selector = selectors.DefaultSelector()
        self._sockets: list[socket.socket] = []
        self._bound_paths: list[Path] = []
        self._stop = threading.Event()
        self._active = {"controller": 0, "runtime": 0, "admin": 0, "inference": 0}
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)

    def __enter__(self) -> "ProxyServer":
        self.directory.mkdir(parents=True, exist_ok=True)
        endpoints = [("controller", "control.sock", self.controller_gid),
                     ("runtime", "tool.sock", self.runtime_gid),
                     ("runtime_ingress", "ingress.sock", self.runtime_gid)]
        if self.approval_authority is not None:
            endpoints.append(("admin", "admin.sock", self.admin_gid))
        if self.inference_authority is not None:
            endpoints.append(("inference", "inference.sock", 21011))
        try:
            for role, name, gid in endpoints:
                path = Path(self.inference_directory if role == "inference" else self.directory) / name
                # lexists covers dangling links, which are not our endpoint.
                if os.path.lexists(path):
                    raise RuntimeError("socket_path_exists")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    listener.bind(str(path))
                    self._bound_paths.append(path)
                    listener.listen(16)
                    os.chmod(path, 0o660 if role == "admin" else self.socket_mode)
                    if gid is not None:
                        os.chown(path, -1, gid)
                    self._selector.register(listener, selectors.EVENT_READ, role)
                    self._sockets.append(listener)
                except BaseException:
                    listener.close()
                    raise
        except BaseException:
            # Bootstrap failures retire only endpoints bound by this instance.
            for listener in self._sockets:
                listener.close()
            self._selector.close()
            for path in self._bound_paths:
                path.unlink(missing_ok=True)
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        for listener in self._sockets:
            self._selector.unregister(listener)
            listener.close()
        # Do not export SQLite or delete sockets while a handler can still commit.
        # recv is bounded at ten seconds and SQLite busy timeout at ten seconds.
        deadline = time.monotonic() + 22
        with self._idle:
            while any(self._active.values()):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("proxy_handlers_unclosed_preserve_evidence")
                self._idle.wait(remaining)
        self._selector.close()
        for path in self._bound_paths:
            path.unlink(missing_ok=True)

    def serve_forever(self, *, provisioning_poll=None) -> None:
        while not self._stop.is_set():
            if provisioning_poll is not None:
                provisioning_poll()
            if self._stop.is_set():
                break
            try:
                ready = self._selector.select(timeout=0.2)
            except (OSError, ValueError):
                if self._stop.is_set():
                    return
                raise
            for key, _mask in ready:
                try:
                    connection, _address = key.fileobj.accept()
                except OSError:
                    if self._stop.is_set():
                        return
                    raise
                role_bucket = "runtime" if key.data == "runtime_ingress" else key.data
                with self._lock:
                    if self._stop.is_set() or self._active[role_bucket] >= 16:
                        connection.close()
                        continue
                    self._active[role_bucket] += 1
                try:
                    threading.Thread(target=self._handle, args=(connection, key.data), daemon=True).start()
                except BaseException:
                    connection.close()
                    with self._idle:
                        self._active[role_bucket] -= 1
                        self._idle.notify_all()
                    raise

    def stop(self) -> None:
        self._stop.set()

    def _handle(self, connection: socket.socket, socket_role: str) -> None:
        try:
            connection.settimeout(MAX_REQUEST_SECONDS)
            raw_peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw_peer)
            expected = (21011 if socket_role == "inference" else 21010 if socket_role == "admin" else
                        self.controller_uid if socket_role == "controller" else self.runtime_uid)
            # Consume one bounded packet before replying. Closing a SEQPACKET socket
            # with unread input can turn the explicit denial into ECONNRESET.
            raw, _ancillary, flags, _address = connection.recvmsg(MAX_MESSAGE_BYTES + 1)
            if uid != expected:
                self._send(connection, {"ok": False, "error_code": "denied"})
                return
            if not raw or len(raw) > MAX_MESSAGE_BYTES or flags & socket.MSG_TRUNC:
                self._send(connection, {"ok": False, "error_code": "invalid_args"})
                return
            try:
                if socket_role == "inference":
                    from skillloop.protocol import decode_json
                    request = decode_json(raw)
                    if type(request) is not dict:
                        raise ProxyError("invalid_args")
                    end = _deadline(request["deadline"])
                    with self.store.rpc_window(end):
                        if request.get("kind") == "RuntimeInferenceReservationRequest":
                            result = self.inference_authority.reserve(request)
                        else:
                            result = self.inference_authority.complete(request)
                    self._send(connection, {"ok": True, "result": result})
                    return
                if socket_role == "runtime_ingress":
                    call = parse_envelope(raw)
                    if call["kind"] != "ToolCall":
                        raise ProxyError("denied")
                    digest = self.store.stage_object(call, trusted_role="runtime")
                    self._send(connection, {"ok": True, "call_digest": digest})
                    return
                request = parse_control(raw)
                result = self.dispatch(request, socket_role)
                self._send(connection, {"ok": True, "result": result})
            except (ProxyError, ProtocolError, KeyError, TypeError, ValueError) as error:
                code = error.code if isinstance(error, ProxyError) else "invalid_args"
                self._send(connection, {"ok": False, "error_code": code})
            except sqlite3.Error:
                # A store failure is not proof that an operation never committed.
                # The controller must recover its durable operation before retrying.
                self._send(connection, {"ok": False, "error_code": "runtime_error"})
        except (OSError, TimeoutError):
            pass
        finally:
            connection.close()
            with self._lock:
                self._active["runtime" if socket_role == "runtime_ingress" else socket_role] -= 1
                self._idle.notify_all()

    @staticmethod
    def _send(connection: socket.socket, value: dict[str, Any]) -> None:
        raw = canonical_json_line(value)
        if len(raw) > MAX_MESSAGE_BYTES:
            raw = canonical_json_line({"ok": False, "error_code": "runtime_error"})
        connection.sendall(raw)

    def dispatch(self, request: dict[str, Any], role: str) -> dict[str, Any]:
        """Role is supplied only after SO_PEERCRED verification in _handle."""
        if request.get('kind')!='ControlRequest':raise ProxyError('invalid_args')
        end=_deadline(request['body']['deadline'])
        with self.store.rpc_window(end):
            return self._dispatch_in_window(request,role)

    def _dispatch_in_window(self, request: dict[str, Any], role: str) -> dict[str, Any]:
        if request["kind"] != "ControlRequest":
            raise ProxyError("invalid_args")
        body = request["body"]
        remaining = _deadline(body["deadline"]) - datetime.now(timezone.utc)
        if remaining <= timedelta(0):
            raise ProxyError("expired")
        if remaining > timedelta(seconds=MAX_REQUEST_SECONDS):
            raise ProxyError("invalid_args")
        method, params = body["method"], body["params"]
        if role == "admin":
            if self.approval_authority is None:
                raise ProxyError("denied")
            if method == "get_operation":
                return self.approval_authority.operation_status(params["operation_ref"])
            return self.approval_authority.approve(request, role)
        controller = {"activate_approval", "revoke_approval", "start_run",
                      "cancel_run", "recover_operation", "get_operation", "reserve_campaign"}
        runtime = {"register_call_batch", "read_resource", "build_artifact", "write_artifact",
                   "validate_artifact", "prepare_publication", "publish_artifact", "record_terminal_output", "get_operation"}
        if method not in (controller if role == "controller" else runtime if role == "runtime" else set()):
            raise ProxyError("denied")
        opid = body["operation_id"]
        digest = digest_jcs({"deployment_epoch": self.store.deployment_epoch,
                             "role": role, "method": method, "params": params})
        if method == "activate_approval":
            result = self.store.activate_approval(params["approval_digest"], params["expected_trust_revision"],
                operation_id=opid, request_digest=digest)
            return make_control("ApprovalResult", {"operation_id": opid, "approval_ref": result["approval_digest"],
                "effective_trust_revision": result["trust_revision"], "state": result["state"],
                "committed_at": result["committed_at"], "expires_at": result["expires_at"]})
        if method == "revoke_approval":
            result = self.store.revoke_approval(params["approval_digest"], params["expected_trust_revision"],
                operation_id=opid, request_digest=digest)
            return make_control("ApprovalResult", {"operation_id": opid, "approval_ref": result["approval_digest"],
                "effective_trust_revision": result["trust_revision"], "state": result["state"],
                "committed_at": result["committed_at"], "expires_at": result["expires_at"]})
        if method == 'reserve_campaign':
            if not hasattr(self.store,'reserve_campaign'):raise ProxyError('denied')
            return self.store.reserve_campaign(params['campaign_digest'],params['plan_digest'],
                operation_id=opid,request_digest=digest)
        if method == "start_run":
            return self.store.start_run(params["run_request_digest"], params["task_binding_digest"],
                operation_id=opid, request_digest=digest)
        if method == "cancel_run":
            prefix='admin campaign cancellation:'
            if params['reason'].startswith(prefix):
                # This method is already restricted to the kernel-authenticated
                # Controller. Its Admin delegation pins the exact campaign.
                from skillloop.proxy.storage import FormalStorageStore
                if not isinstance(self.store,FormalStorageStore):raise ProxyError('denied')
                result=self.store.cancel_campaign_run(params['reason'][len(prefix):],
                    params['run_id'],params['expected_fence'],operation_id=opid,request_digest=digest)
            else:
                result = self.store.cancel_run(params["run_id"], params["expected_fence"],
                    operation_id=opid, request_digest=digest)
            if self.on_cancel is not None:
                self.on_cancel()
            return make_control("CancellationResult", {"campaign_public_ref": result["campaign_id"],
                "run_id": result["run_id"], "effective_fence": result["fence"],
                "committed_at": result["committed_at"]})
        if method == "recover_operation":
            result = self.store.recover_tool(params["run_id"], params["tool"], params["idempotency_key"])
            return make_control("RecoveryResult", result)
        if method == 'record_terminal_output':
            return self.store.record_terminal_output(params['run_id'],params['fence'],params['raw_output_digest'],
                operation_id=opid,request_digest=digest)
        if method == "register_call_batch":
            result = self.store.register_call_batch(params["run_id"], params["fence"],
                                                    params["response_id"], params["calls"])
            return make_control("RegistrationResult", result)
        if method in TOOL_NAMES:
            return self.store.execute_call(params["call_digest"], method)
        if method == "get_operation":
            return make_control("OperationStatus", self.store.get_operation(params["operation_ref"], role))
        raise ProxyError("denied")


TOOL_NAMES = frozenset({"read_resource", "build_artifact", "write_artifact",
                        "validate_artifact", "prepare_publication", "publish_artifact"})
