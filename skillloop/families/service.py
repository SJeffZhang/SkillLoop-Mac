"""Pinned family capability providers over Linux authenticated API4 RPC.

Digest comparison verifies approved bytes. SO_PEERCRED authenticates both peers;
caller-supplied roles never grant access. Existing local registries are unchanged.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import struct
import threading
import uuid

from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import (
    ProtocolError, canonical_json_line, decode_json, digest_bytes, digest_jcs,
    make_envelope, parse_envelope, validate_envelope,
)

MAX_PACKET = 262144
FAMILIES = frozenset({'table-report', 'markdown-index'})


def plugin_manifest(registry: FamilyRegistry, family_id: str) -> dict:
    if family_id not in FAMILIES:
        raise ProtocolError('unknown_family')
    capability = registry.capability_handshake()
    capability['profiles'] = [p for p in capability['profiles'] if p['family_id'] == family_id]
    implementation = digest_jcs({
        'provider_source': digest_bytes(Path(__file__).read_bytes()),
        'capability_digest': digest_jcs(capability),
    })
    return make_envelope('PluginManifest', {
        'plugin_id': family_id, 'api_major': 4, 'plugin_digest': implementation,
        'methods': ['plugin.handshake'], 'request_kinds': ['RPCRequest'],
        'response_kinds': ['RPCResponse'], 'trusted_role': 'registry',
        'memory_limit_bytes': 268435456, 'timeout_ms': 10000,
    })


def family_output(registry: FamilyRegistry, family_id: str) -> dict:
    manifest = plugin_manifest(registry, family_id)
    capability = registry.capability_handshake()
    capability['profiles'] = [p for p in capability['profiles'] if p['family_id'] == family_id]
    return {'manifest': manifest, 'capability': capability}


def validate_output(value: dict, approved: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {'manifest', 'capability'}:
        raise ProtocolError('plugin_output_shape')
    validate_envelope(value['manifest'])
    if value != approved:
        raise ProtocolError('plugin_capability_mismatch')
    return value


def _peer(connection: socket.socket) -> tuple[int, int, int]:
    return struct.unpack('3i', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))


def _receive(connection: socket.socket) -> bytes:
    raw, _ancillary, flags, _address = connection.recvmsg(MAX_PACKET + 1)
    if not raw or len(raw) > MAX_PACKET or flags & socket.MSG_TRUNC:
        raise ProtocolError('plugin_packet_size')
    return raw


def _linux() -> None:
    if not hasattr(socket, 'SO_PEERCRED') or not hasattr(socket, 'SOCK_SEQPACKET'):
        raise RuntimeError('Linux SO_PEERCRED and SEQPACKET required')


class FamilyPluginServer:
    """A reviewed registry provider. It exposes only plugin.handshake."""
    def __init__(self, path: Path, *, family_id: str, caller_uid: int,
                 socket_gid: int, campaign_id: str, fence: int,
                 registry: FamilyRegistry | None = None):
        _linux()
        if type(caller_uid) is not int or caller_uid < 0 or type(fence) is not int or fence < 0:
            raise ValueError('invalid_registry_identity')
        self.path = Path(path)
        self.caller_uid = caller_uid
        self.socket_gid = socket_gid
        self.campaign_id = campaign_id
        self.fence = fence
        self.output = family_output(registry or FamilyRegistry(), family_id)
        self._stop = threading.Event()
        self.listener: socket.socket | None = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            raise RuntimeError('plugin_socket_already_exists')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o660)
        os.chown(self.path, -1, self.socket_gid)
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        return self

    def stop(self):
        self._stop.set()

    def __exit__(self, *_):
        self.stop()
        if self.listener is not None:
            self.listener.close()
        self.path.unlink(missing_ok=True)

    def serve_forever(self):
        if self.listener is None:
            raise RuntimeError('plugin_not_open')
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(10)
                request_id = 'invalid-request'
                error = None
                try:
                    _pid, uid, _gid = _peer(connection)
                    raw = _receive(connection)
                    request = parse_envelope(raw)
                    if request['kind'] != 'RPCRequest':
                        raise ProtocolError('plugin_request_kind')
                    body = request['body']
                    request_id = body['request_id']
                    if uid != self.caller_uid:
                        raise ProtocolError('plugin_caller_uid')
                    if (body['method'] != 'plugin.handshake' or
                        body['campaign_id'] != self.campaign_id or
                        body['fencing_token'] != self.fence or
                        body['input_digest'] != self.output['manifest']['digest']):
                        raise ProtocolError('plugin_request_binding')
                    deadline = datetime.fromisoformat(body['deadline'].replace('Z', '+00:00'))
                    if deadline <= datetime.now(timezone.utc):
                        error = 'deadline_exceeded'
                except (ProtocolError, OSError, TimeoutError):
                    error = 'invalid_input'
                try:
                    response = make_envelope('RPCResponse', {
                        'request_id': request_id, 'status': 'error' if error else 'ok',
                        'output_digest': None if error else digest_jcs(self.output),
                        'error_code': error, 'retryable': False,
                    })
                    connection.sendall(canonical_json_line(response))
                    if not error:
                        connection.sendall(canonical_json_line(self.output))
                except (OSError, TimeoutError):
                    pass


def authenticated_handshake(path: Path, *, approved_output: dict,
                            provider_uid: int, campaign_id: str, fence: int,
                            deadline: str) -> tuple[dict, dict]:
    """Only trusted configuration supplies provider_uid and approved_output."""
    _linux()
    if type(provider_uid) is not int or provider_uid < 0:
        raise ValueError('invalid_provider_uid')
    validate_output(approved_output, approved_output)
    request = make_envelope('RPCRequest', {
        'request_id': 'family-' + uuid.uuid4().hex, 'method': 'plugin.handshake',
        'campaign_id': campaign_id, 'fencing_token': fence,
        'input_digest': approved_output['manifest']['digest'], 'deadline': deadline,
    })
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        pid, uid, gid = _peer(connection)
        if uid != provider_uid:
            raise ProtocolError('plugin_provider_uid')
        connection.sendall(canonical_json_line(request))
        response = parse_envelope(_receive(connection))
        if (response['kind'] != 'RPCResponse' or
            response['body']['request_id'] != request['body']['request_id'] or
            response['body']['status'] != 'ok'):
            raise ProtocolError('plugin_response_binding')
        output = decode_json(_receive(connection))
        if response['body']['output_digest'] != digest_jcs(output):
            raise ProtocolError('plugin_response_digest')
        validate_output(output, approved_output)
    receipt = {'request_digest': request['digest'], 'response_digest': response['digest'],
               'manifest_digest': output['manifest']['digest'], 'output_digest': digest_jcs(output),
               'actual_provider_pid': pid, 'actual_provider_uid': uid, 'actual_provider_gid': gid,
               'authenticated_transport': 'Linux_SO_PEERCRED_SEQPACKET'}
    return copy.deepcopy(output), receipt


class AuthenticatedFamilyRegistry(FamilyRegistry):
    """Explicit opt-in ProxyStore registry, admitted by two independent peers."""
    def __init__(self, peers: dict[str, tuple[Path, int]], *, campaign_id: str,
                 fence: int, deadline: str):
        super().__init__()
        if set(peers) != FAMILIES:
            raise ProtocolError('plugin_missing_family')
        self.authentication_receipts = {}
        for family_id in sorted(peers):
            path, uid = peers[family_id]
            approved = family_output(self, family_id)
            _output, receipt = authenticated_handshake(
                path, approved_output=approved, provider_uid=uid,
                campaign_id=campaign_id, fence=fence, deadline=deadline)
            self.authentication_receipts[family_id] = receipt


def main():
    parser = argparse.ArgumentParser(description='Strict authenticated family registry provider')
    parser.add_argument('--family', required=True, choices=sorted(FAMILIES))
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--caller-uid', required=True, type=int)
    parser.add_argument('--socket-gid', required=True, type=int)
    parser.add_argument('--campaign', required=True)
    parser.add_argument('--fence', required=True, type=int)
    args = parser.parse_args()
    with FamilyPluginServer(args.socket, family_id=args.family, caller_uid=args.caller_uid,
                            socket_gid=args.socket_gid, campaign_id=args.campaign,
                            fence=args.fence) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
