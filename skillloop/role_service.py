"""Frozen-role control object service with durable, operator-provisioned read grants.

Provisioning is a trusted local API, not credential or qualification issuance.
No private object is resolved from a digest without an exact active role grant.
"""
from __future__ import annotations

import json
import os
import selectors
import socket
import sqlite3
import stat
import struct
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs, validate_envelope
from skillloop.proxy.store import ProxyError
from skillloop.proxy.wire import make_control, parse_control, validate_control

LIMIT = 262144
READ_METHODS = frozenset({'read_private_evidence', 'read_dev_evidence', 'read_import_snapshot',
                         'read_public_projection', 'read_authoritative_manifest'})


def utc(value):
    t = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if t.tzinfo is None:
        raise ValueError('timezone_required')
    return t.astimezone(timezone.utc)


def valid_result(value):
    if value.get('kind') in {'PublicReport'}:
        validate_control(value)
    else:
        validate_envelope(value)
    if len(canonical_json_line({'ok': True, 'result': value})) > LIMIT:
        raise ValueError('result_size')
    return value


class RoleRegistry:
    """Only the frozen RPC profile and method registry establish role authority."""
    def __init__(self, spec_directory: Path):
        directory = Path(spec_directory)
        rpc_raw = (directory / 'rpc.json').read_bytes()
        methods_raw = (directory / 'control-methods.json').read_bytes()
        rpc, methods = decode_json(rpc_raw), decode_json(methods_raw)
        if rpc['api_major'] != 4 or rpc['caller_supplied_role_authorizes'] is not False:
            raise ValueError('rpc_profile')
        roles = {r['role']: r['uid'] for r in rpc['roles']}
        if len(roles) != len(rpc['roles']) or len(set(roles.values())) != len(roles):
            raise ValueError('duplicate_role_uid')
        results = {m['method']: m['result_kind'] for m in methods['methods']}
        permissions = {role: frozenset(m['method'] for m in methods['methods']
                                      if role in m['allowed_roles']) for role in roles}
        for r in rpc['roles']:
            if permissions[r['role']] != frozenset(r['methods']):
                raise ValueError('role_method_contract_conflict')
        self.uids = MappingProxyType(roles)
        self.methods = MappingProxyType(permissions)
        self.results = MappingProxyType(results)
        self.contract_digest = digest_jcs({'rpc': digest_bytes(rpc_raw), 'methods': digest_bytes(methods_raw)})


class RoleObjectStore:
    """Separate protected SQLite store; exact role/method/params grants, epoch fenced."""
    def __init__(self, path: Path, epoch: str, registry: RoleRegistry):
        self.path, self.epoch, self.registry = Path(path), epoch, registry
        parent = self.path.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise ValueError('private_store_directory')
        if self.path.is_symlink():
            raise ValueError('database_symlink')
        if self.path.exists():
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError('private_database')
        else:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        with closing(self.connect()) as db:
            db.executescript('''BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS identity(epoch TEXT, contract TEXT);
            CREATE TABLE IF NOT EXISTS roles(role TEXT PRIMARY KEY,generation INTEGER,active INTEGER,deadline TEXT);
            CREATE TABLE IF NOT EXISTS grants(role TEXT,generation INTEGER,method TEXT,params_digest TEXT,result BLOB,
                PRIMARY KEY(role,generation,method,params_digest));
            CREATE TABLE IF NOT EXISTS operations(operation_id TEXT PRIMARY KEY,role TEXT,generation INTEGER,
                request_digest TEXT,result BLOB);''')
            row = db.execute('SELECT epoch,contract FROM identity').fetchone()
            if row and row != (epoch, registry.contract_digest):
                raise ValueError('deployment_identity_mismatch')
            if not row:
                db.execute('INSERT INTO identity VALUES(?,?)', (epoch, registry.contract_digest))
            db.commit()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def activate_role(self, role: str, deadline: str):
        if role not in self.registry.uids or role == 'proxy' or utc(deadline) <= datetime.now(timezone.utc):
            raise ValueError('role_activation')
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT generation FROM roles WHERE role=?', (role,)).fetchone()
            generation = row[0] + 1 if row else 1
            db.execute('INSERT OR REPLACE INTO roles VALUES(?,?,1,?)', (role, generation, deadline))
            db.commit()
        return generation

    def revoke_role(self, role: str):
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE roles SET generation=generation+1,active=0 WHERE role=?', (role,))
            db.commit()

    def grant_read(self, role: str, method: str, params: dict, result: dict):
        if method not in READ_METHODS or method not in self.registry.methods.get(role, ()):
            raise ProxyError('denied')
        valid_result(result)
        if result['kind'] != self.registry.results[method]:
            raise ValueError('result_kind')
        if method in {'read_private_evidence', 'read_dev_evidence'} and params.get('evidence_index_digest') != result['digest']:
            raise ValueError('evidence_digest_binding')
        if method == 'read_import_snapshot' and params.get('snapshot_digest') != result['digest']:
            raise ValueError('snapshot_digest_binding')
        # Strict frozen parameter shape is validated through a real ControlRequest.
        make_control('ControlRequest', {'operation_id': 'provision', 'deadline': '2099-01-01T00:00:00Z',
                     'method': method, 'params': params})
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            generation = self._active(db, role)
            db.execute('INSERT INTO grants VALUES(?,?,?,?,?)',
                       (role, generation, method, digest_jcs(params), canonical_json_line(result)))
            db.commit()

    @staticmethod
    def _active(db, role):
        row = db.execute('SELECT generation,active,deadline FROM roles WHERE role=?', (role,)).fetchone()
        if not row or not row[1]:
            raise ProxyError('denied')
        if utc(row[2]) <= datetime.now(timezone.utc):
            raise ProxyError('expired')
        return row[0]

    def dispatch(self, request: dict, role: str):
        validate_control(request)
        if request['kind'] != 'ControlRequest':
            raise ProxyError('invalid_args')
        body = request['body']
        seconds = (utc(body['deadline']) - datetime.now(timezone.utc)).total_seconds()
        if seconds <= 0:
            raise ProxyError('expired')
        if seconds > 10:
            raise ProxyError('invalid_args')
        method = body['method']
        if method not in self.registry.methods.get(role, ()) or method not in READ_METHODS | {'get_operation'}:
            raise ProxyError('denied')
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            generation = self._active(db, role)
            if method == 'get_operation':
                row = db.execute('SELECT role,generation,result FROM operations WHERE operation_id=?',
                                 (body['params']['operation_ref'],)).fetchone()
                if not row or row[:2] != (role, generation):
                    raise ProxyError('denied')
                result = decode_json(row[2])
                return make_control('OperationStatus', {'operation_ref': body['params']['operation_ref'],
                    'state': 'completed', 'result_kind': result['kind'], 'result_digest': result['digest'],
                    'error_code': None})
            # Check current grant even on replay: revocation/expiry cannot replay private bytes.
            granted = db.execute('SELECT result FROM grants WHERE role=? AND generation=? AND method=? AND params_digest=?',
                       (role, generation, method, digest_jcs(body['params']))).fetchone()
            if not granted:
                raise ProxyError('denied')
            row = db.execute('SELECT role,generation,request_digest,result FROM operations WHERE operation_id=?',
                             (body['operation_id'],)).fetchone()
            if row:
                if row[:3] != (role, generation, request['digest']):
                    raise ProxyError('denied')
                return valid_result(decode_json(row[3]))
            result = valid_result(decode_json(granted[0]))
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',
                       (body['operation_id'], role, generation, request['digest'], granted[0]))
            db.commit()
            return result


class RoleObjectServer:
    """Distinct role sockets and actual SO_PEERCRED; no caller role field authority."""
    def __init__(self, store: RoleObjectStore, directory: Path, socket_gids: dict[str, int]):
        if not hasattr(socket, 'SO_PEERCRED'):
            raise RuntimeError('Linux_required')
        self.store, self.directory, self.gids = store, Path(directory), dict(socket_gids)
        if set(self.gids) - set(store.registry.uids) or 'proxy' in self.gids:
            raise ValueError('socket_role')
        self.selector = selectors.DefaultSelector()
        self.listeners = []
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.active = {role: 0 for role in self.gids}
        self.idle = threading.Condition(self.lock)

    def __enter__(self):
        self.directory.mkdir(exist_ok=True)
        try:
            for role, gid in self.gids.items():
                path = self.directory / (role + '.sock')
                if os.path.lexists(path):
                    raise ValueError('socket_exists')
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                listener.bind(str(path))
                self.listeners.append((listener, path))
                os.chmod(path, 0o660)
                os.chown(path, -1, gid)
                listener.listen(16)
                self.selector.register(listener, selectors.EVENT_READ, role)
            return self
        except BaseException:
            self.__exit__()
            raise

    def serve_forever(self):
        while not self.stop_event.is_set():
            for key, _ in self.selector.select(0.1):
                conn, _ = key.fileobj.accept()
                role = key.data
                with self.lock:
                    if self.active[role] >= 16:
                        conn.close()
                        continue
                    self.active[role] += 1
                threading.Thread(target=self._handle, args=(conn, role), daemon=True).start()

    def _handle(self, conn, role):
        try:
            conn.settimeout(10)
            pid, uid, gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            raw, _, flags, _ = conn.recvmsg(LIMIT + 1)
            if uid != self.store.registry.uids[role]:
                reply = {'ok': False, 'error_code': 'denied'}
            elif not raw or len(raw) > LIMIT or flags & socket.MSG_TRUNC:
                reply = {'ok': False, 'error_code': 'invalid_args'}
            else:
                try:
                    reply = {'ok': True, 'result': self.store.dispatch(parse_control(raw), role)}
                except (ProxyError, ValueError, KeyError, TypeError) as exc:
                    reply = {'ok': False, 'error_code': exc.code if isinstance(exc, ProxyError) else 'invalid_args'}
                except sqlite3.Error:
                    reply = {'ok': False, 'error_code': 'runtime_error'}
            conn.sendall(canonical_json_line(reply))
        except OSError:
            pass
        finally:
            conn.close()
            with self.idle:
                self.active[role] -= 1
                self.idle.notify_all()

    def stop(self):
        self.stop_event.set()

    def __exit__(self, *_):
        self.stop()
        with self.idle:
            self.idle.wait_for(lambda: not any(self.active.values()), timeout=11)
        for listener, path in self.listeners:
            listener.close()
            path.unlink(missing_ok=True)
        self.selector.close()
