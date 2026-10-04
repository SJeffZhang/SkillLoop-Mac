"""Proxy-owned approval issuer for the frozen authenticated administrator methods.

The immutable deployment catalog is provisioned by trusted bootstrap code. RPC
clients only select exact catalog digests; they cannot upload a domain or model.
Approval issuance and effective trust revision commit in the business database.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from types import MappingProxyType

from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs, make_envelope, validate_envelope
from skillloop.proxy.store import ProxyError, _now, _parse, _stamp
from skillloop.proxy.wire import make_control, validate_control


class ApprovalAuthority:
    def __init__(self, store, *, domains, configurations, factories):
        if os.geteuid() != 21003:
            raise PermissionError('approval_proxy_uid_required')
        info = store.path.lstat()
        parent = store.path.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or store.path.is_symlink()
                or store.path.parent.is_symlink() or info.st_uid != 21003
                or parent.st_uid != 21003 or stat.S_IMODE(info.st_mode) != 0o600
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise PermissionError('approval_business_store_custody')
        self.store = store
        catalog = {}
        factory_raw = (Path(__file__).resolve().parents[2] / 'specs/v2.2/families/private-suite-factory.json').read_bytes()
        factory_profile = decode_json(factory_raw)
        for category, records in (('domain', domains), ('config', configurations), ('factory', factories)):
            for key, value in records.items():
                if type(value) is not dict:
                    raise ValueError('approval_catalog_object')
                if category == 'domain':
                    validate_envelope(value)
                    if value['kind'] != 'AuthorizationDomain' or key != value['digest']:
                        raise ValueError('approval_domain_catalog')
                elif category == 'factory':
                    if key != digest_bytes(factory_raw) or value != factory_profile:
                        raise ValueError('approval_factory_source_pin')
                elif key != digest_jcs(value):
                    raise ValueError('approval_catalog_digest')
                catalog[(category, key)] = canonical_json_line(value)
        self.catalog = MappingProxyType(catalog)
        identity = digest_jcs({category: dict(records) for category, records in
                              (('domain', domains), ('config', configurations), ('factory', factories))})
        with store._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS approval_catalog_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS issued_domain_approvals(approval_ref TEXT PRIMARY KEY, config_digest TEXT NOT NULL, factory_profile_digest TEXT NOT NULL, factory_approval_ref TEXT NOT NULL, operation TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS factory_approvals(profile TEXT PRIMARY KEY, approval_ref TEXT NOT NULL, expires_at TEXT, trust_revision INTEGER NOT NULL)')
            previous = db.execute('SELECT digest FROM approval_catalog_identity WHERE singleton=1').fetchone()
            if previous and previous[0] != identity:
                raise ValueError('approval_catalog_changed_requires_new_deployment')
            db.execute('INSERT OR IGNORE INTO approval_catalog_identity VALUES(1,?)', (identity,))

    def _object(self, category, digest):
        raw = self.catalog.get((category, digest))
        if raw is None:
            raise ProxyError('denied')
        return decode_json(raw)

    def approve(self, request, role):
        # The server supplies role only after checking kernel peer identity.
        if os.geteuid() != 21003 or role != 'admin':
            raise ProxyError('denied')
        validate_control(request)
        if request['kind'] != 'ControlRequest':
            raise ProxyError('invalid_args')
        method, params = request['body']['method'], request['body']['params']
        if method not in {'approve_domain', 'approve_factory'}:
            raise ProxyError('denied')
        operation = request['body']['operation_id']
        fingerprint = digest_jcs({'deployment_epoch': self.store.deployment_epoch,
                                 'role': role, 'method': method, 'params': params})
        expiry = params['expires_at']
        # Core ApprovalRecord requires exact seconds UTC. Do not round client TTL.
        expiry_time = _parse(expiry) if expiry is not None else None
        with self.store._transaction() as db:
            old = db.execute('SELECT role,method,request_digest,result_json FROM operations WHERE operation_id=?', (operation,)).fetchone()
            if old:
                if tuple(old[:3]) != ('admin', method, fingerprint):
                    raise ProxyError('version_conflict')
                return decode_json(old[3])
            if expiry_time is not None and expiry_time <= _now():
                raise ProxyError('expired')
            self._object('factory', params['factory_profile_digest'])
            domain = None
            if method == 'approve_domain':
                domain = self._object('domain', params['domain_digest'])
                self._object('config', params['config_digest'])
                if domain['body']['contract_digest'] != params['contract_digest']:
                    raise ProxyError('denied')
                factory = db.execute('SELECT expires_at,approval_ref FROM factory_approvals WHERE profile=?', (params['factory_profile_digest'],)).fetchone()
                if factory is None:
                    raise ProxyError('approval_required')
                if factory[0] is not None:
                    if _parse(factory[0]) <= _now():
                        raise ProxyError('expired')
                    if expiry_time is None or expiry_time > _parse(factory[0]):
                        raise ProxyError('invalid_args')
            revision = db.execute('SELECT trust_revision FROM trust_state WHERE singleton=1').fetchone()[0] + 1
            if revision > 9007199254740991:
                raise ProxyError('version_conflict')
            now = _stamp(_now())
            if domain is None:
                ref = digest_jcs({'deployment_epoch': self.store.deployment_epoch, 'factory': params['factory_profile_digest'],
                                 'operation_id': operation, 'revision': revision, 'issued_at': now, 'expires_at': expiry})
                db.execute('INSERT OR REPLACE INTO factory_approvals VALUES(?,?,?,?)',
                           (params['factory_profile_digest'], ref, expiry, revision))
            else:
                approval = make_envelope('ApprovalRecord', {
                    'approval_id': operation, 'authorization_domain_digest': domain['digest'],
                    'contract_digest': params['contract_digest'], 'factory_rule_digest': params['factory_profile_digest'],
                    'config_digest': params['config_digest'], 'issuer': 'administrator',
                    'issued_at': now, 'expires_at': expiry, 'trust_revision': revision, 'state': 'active'})
                ref = approval['digest']
                db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,'active',?,?,?)",
                           (ref, domain['digest'], params['contract_digest'], domain['body']['tenant_id'],
                            canonical_json_line(domain), expiry, revision, now))
                db.execute('INSERT INTO issued_domain_approvals VALUES(?,?,?,?,?)',
                           (ref, params['config_digest'], params['factory_profile_digest'], factory[1], operation))
                for value in (domain, approval):
                    db.execute("INSERT OR IGNORE INTO staged_objects VALUES(?,?,?,'admin')",
                               (value['digest'], value['kind'], canonical_json_line(value)))
            result = make_control('ApprovalResult', {'operation_id': operation, 'approval_ref': ref,
                'effective_trust_revision': revision, 'state': 'active', 'committed_at': now, 'expires_at': expiry})
            db.execute('UPDATE trust_state SET trust_revision=? WHERE singleton=1', (revision,))
            db.execute("INSERT INTO accepted_events(run_id,event_type,event_digest,committed_at) VALUES(NULL,?,?,?)",
                       (method, result['digest'], now))
            self.store._record_operation(db, operation, 'admin', None, fingerprint, method, result)
            return result

    def operation_status(self, operation):
        with self.store._transaction() as db:
            row = db.execute('SELECT role,result_json FROM operations WHERE operation_id=?', (operation,)).fetchone()
            if not row or row[0] != 'admin':
                raise ProxyError('denied')
            result = decode_json(row[1])
            return make_control('OperationStatus', {'operation_ref': operation, 'state': 'completed',
                'result_kind': result['kind'], 'result_digest': result['digest'], 'error_code': None})
