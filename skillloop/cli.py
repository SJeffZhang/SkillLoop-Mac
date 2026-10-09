"""API4 operator CLI with exact-source import/scan and authenticated report/promote."""
from __future__ import annotations
import argparse
import os
import sqlite3
import sys
import subprocess
import socket
import struct
import uuid
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .protocol import ProtocolError, canonical_json_line, decode_json, digest_bytes, digest_jcs, validate_envelope
from .source import import_git_package
from .proxy.wire import make_control, validate_control
from .runtime.client import ProxyRPCError

class SyntaxError64(ValueError):
    pass

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SyntaxError64("invalid_arguments")


def _operation_result(operation_id: str, parameters: dict, produce) -> dict:
    # This is a control-owned journal, never a path supplied by the Skill package.
    state = os.environ.get("SKILLLOOP_CONTROL_DIR")
    if not state or not operation_id or len(operation_id) > 256:
        raise PermissionError("operation_control_directory_required")
    root = Path(state)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stat = root.lstat()
    if root.is_symlink() or stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise PermissionError("operation_control_directory_private_owner_required")
    path = root / "import-operations.sqlite"
    if path.is_symlink():
        raise PermissionError("operation_journal_symlink")
    prior = os.umask(0o077)
    try:
        with sqlite3.connect(path, timeout=5) as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, parameters TEXT NOT NULL, result BLOB NOT NULL)")
            db.execute("BEGIN IMMEDIATE")
            fingerprint = digest_jcs(parameters)
            row = db.execute("SELECT parameters,result FROM operations WHERE id=?", (operation_id,)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise ProtocolError("operation_id_parameter_conflict")
                return decode_json(row[1])
            result = produce()
            db.execute("INSERT INTO operations VALUES (?,?,?)", (operation_id, fingerprint, canonical_json_line(result)))
            return result
    finally:
        os.umask(prior)


def _report(campaign: str) -> dict:
    # Endpoint configuration belongs to the operator deployment, never a package.
    # The frozen report UID and server UID are checked against real kernel peers.
    if not hasattr(socket, "SO_PEERCRED") or os.geteuid() != 21009:
        raise PermissionError("report_role_required")
    directory = os.environ.get("SKILLLOOP_REPORT_SOCKET_DIR")
    if not directory or not Path(directory).is_absolute():
        raise PermissionError("report_endpoint_required")
    request = make_control("ControlRequest", {
        "operation_id": "report-" + uuid.uuid4().hex,
        "deadline": (datetime.now(timezone.utc) + timedelta(seconds=9)).isoformat().replace("+00:00", "Z"),
        "method": "read_public_projection", "params": {"campaign_digest": campaign},
    })
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(10)
        connection.connect(str(Path(directory) / "report.sock"))
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer[1] != 21003:
            raise PermissionError("report_server_identity")
        connection.sendall(canonical_json_line(request))
        raw, _, flags, _ = connection.recvmsg(262145)
    if not raw or len(raw) > 262144 or flags & socket.MSG_TRUNC:
        raise OSError("invalid_report_response")
    try:
        reply = decode_json(raw)
        if type(reply) is not dict or type(reply.get("ok")) is not bool:
            raise ValueError("invalid_response")
        if reply["ok"] is False:
            if set(reply) != {"ok", "error_code"}:
                raise ValueError("invalid_error_response")
            if reply["error_code"] in {"denied", "expired"}:
                raise PermissionError("report_denied")
            if reply["error_code"] == "runtime_error":
                raise TimeoutError("report_unavailable")
            raise ValueError("invalid_error_code")
        if set(reply) != {"ok", "result"}:
            raise ValueError("invalid_success_response")
        result = validate_control(reply["result"])
        if result["kind"] != "PublicReport":
            raise ValueError("unexpected_result_kind")
        return result
    except (ProtocolError, ValueError, KeyError, TypeError) as exc:
        raise OSError("invalid_report_response") from exc


def _input_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 262144:
            raise SyntaxError64("input_document_bound")
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise SyntaxError64("input_document_bound")
    return raw


def _input_document(path: Path) -> dict:
    value = decode_json(_input_bytes(path))
    if type(value) is not dict:
        raise SyntaxError64("input_document_object_required")
    return value


def _admin_approval(args) -> dict:
    from .runtime.client import ProxyClient
    if os.geteuid() != 21010:
        raise PermissionError("administrator_role_required")
    endpoint = os.environ.get("SKILLLOOP_ADMIN_SOCKET_DIR")
    if not endpoint or not Path(endpoint).is_absolute():
        raise PermissionError("administrator_endpoint_required")
    factory_raw = _input_bytes(args.factory_profile)
    if type(decode_json(factory_raw)) is not dict:
        raise SyntaxError64("factory_profile_object_required")
    params = {"factory_profile_digest": digest_bytes(factory_raw), "expires_at": args.expires_at}
    if args.admin_command == "approve-domain":
        domain = validate_envelope(_input_document(args.domain))
        if domain["kind"] != "AuthorizationDomain":
            raise SyntaxError64("authorization_domain_required")
        params.update(domain_digest=domain["digest"],
                      contract_digest=digest_jcs(_input_document(args.contract)),
                      config_digest=digest_jcs(_input_document(args.model_config)))
    method = "approve_domain" if args.admin_command == "approve-domain" else "approve_factory"
    result = ProxyClient(Path(endpoint), expected_server_uid=21003).control_request(
        method, params, operation_id=args.operation_id, admin=True)
    if result["kind"] != "ApprovalResult" or result["body"]["operation_id"] != args.operation_id:
        raise OSError("approval_response_binding")
    return result


def main(argv=None) -> int:
    parser = Parser(prog="skillloop")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    imp = commands.add_parser("import", help="Import exact Git objects as data")
    imp.add_argument("--git-repo", required=True, type=Path)
    imp.add_argument("--commit", required=True)
    imp.add_argument("--skill-path", required=True)
    imp.add_argument("--operation-id")
    scan = commands.add_parser("scan", help="Run the pinned offline scanner on an approved exact SourceSnapshot")
    scan.add_argument("--snapshot", required=True, type=Path)
    scan.add_argument("--scanner-profile", type=Path)
    scan.add_argument("--operation-id")
    report = commands.add_parser("report", help="Read the public campaign projection from the authenticated control service")
    report.add_argument("--campaign", required=True)
    report.add_argument("--format", choices=["json"], default="json")
    promote = commands.add_parser("promote", help="Consume the current Gate-issued qualification and compare-and-swap the active registry")
    promote.add_argument("--campaign", required=True)
    promote.add_argument("--subject", required=True)
    promote.add_argument("--expected-active-revision", required=True, type=int)
    promote.add_argument("--operation-id")
    admin = commands.add_parser("admin", help="Authenticated administrative operations")
    admin_commands = admin.add_subparsers(dest="admin_command", required=True, parser_class=Parser)
    for name in ("approve-domain", "approve-factory"):
        sub = admin_commands.add_parser(name)
        sub.add_argument("--factory-profile", required=True, type=Path)
        sub.add_argument("--operation-id", required=True)
        sub.add_argument("--expires-at")
        if name == "approve-domain":
            sub.add_argument("--domain", required=True, type=Path)
            sub.add_argument("--contract", required=True, type=Path)
            sub.add_argument("--model-config", required=True, type=Path)
    # Remaining syntax is generated from the frozen CLI profile, without new
    # flags or a public RPC method. Trusted operator transport owns dispatch.
    import json
    profile=json.loads((Path(__file__).resolve().parents[1]/'specs/v2.2/operations/cli.json').read_text())
    existing={'import','scan','report','promote','admin approve-domain','admin approve-factory'}
    documents={'snapshot','contract','model-config','factory-profile','domain','finding','evidence',
               'export-manifest','archive','runtime-profile'}
    for spec in profile['commands']:
        name=spec['name']
        if name in existing:continue
        target=admin_commands.add_parser(name.split(' ',1)[1]) if name.startswith('admin ') else commands.add_parser(name)
        for flag in spec['required_flags']+spec['optional_flags']:
            actual=flag.split('=',1)[0];key=actual[2:]
            options={'required':flag in spec['required_flags']}
            if key in documents or key in {'destination','evidence-dir'}:
                if key in {'finding','evidence','archive','export-manifest'}:
                    import re
                    options['type']=lambda value: value if re.fullmatch(r'sha256:[0-9a-f]{64}',value) else Path(value)
                else:options['type']=Path
            if key=='repair-rounds':options.update(type=int,choices=[0,1,2],default=2)
            target.add_argument(actual,**options)
    try:
        args = parser.parse_args(argv)
        from .runtime.operator_client import CONFIG,operator_request
        command=('admin '+args.admin_command) if args.command=='admin' else args.command
        # A dangling or malicious symlink at the formal deployment locator
        # must enter the authenticated reader and fail closed. Path.exists()
        # would silently select the standalone fallback instead.
        if os.path.lexists(CONFIG):
            params={}
            for key,value in vars(args).items():
                if key in {'command','admin_command','operation_id'} or value is None:continue
                params[key]=_input_document(value) if key.replace('_','-') in documents and isinstance(value,Path) else str(value) if isinstance(value,Path) else value
            result=operator_request(command,params,getattr(args,'operation_id',None))
            expected=next(s['stdout_schema'] for s in profile['commands'] if s['name']==command)
            if result['kind']!=expected:raise OSError('operator_frozen_result_kind')
            sys.stdout.buffer.write(canonical_json_line(result))
            if expected in {'CIResult','HardenResult'}:
                verdict=result['body']['verdict']
                return profile['verdict_exit'][verdict]
            return 0
        # Every public command belongs to the one Controller-owned operation
        # store. A standalone component result has no whole-round admission,
        # original ticket or recovery reference and must not look successful.
        raise PermissionError('formal_operator_deployment_required')
    except (SyntaxError64, ProtocolError) as exc:
        print(str(exc), file=sys.stderr)
        return 64
    except ValueError:
        print("invalid_source", file=sys.stderr)
        return 64
    except PermissionError:
        print("permission_denied", file=sys.stderr)
        return 77
    except (TimeoutError, subprocess.TimeoutExpired):
        print("temporary_busy", file=sys.stderr)
        return 75
    except sqlite3.OperationalError as exc:
        code = 75 if "locked" in str(exc) else 74
        print("operation_store_busy" if code == 75 else "operation_store_io", file=sys.stderr)
        return code
    except OSError:
        print("io_error", file=sys.stderr)
        return 74
    except ProxyRPCError as exc:
        code = str(exc)
        if code in {"denied", "approval_required", "expired", "proxy_server_identity_mismatch"}:
            print("permission_denied", file=sys.stderr)
            return 77
        if code == "invalid_args":
            print("invalid_arguments", file=sys.stderr)
            return 64
        print("control_operation_unknown_or_conflicting", file=sys.stderr)
        return 75
