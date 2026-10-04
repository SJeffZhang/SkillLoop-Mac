"""Trusted Evaluator-to-Proxy admission of one committed current task.

This is a dedicated provisioning inbox, not an added role/RPC permission.
The full protected plan and factory bundle never enter the business Proxy.
"""
import base64
from contextlib import closing
import os
import re

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.loader import ApprovedPackageLoader, validate_source_admission
from skillloop.protocol import canonical_json_line, digest_jcs, validate_envelope
from skillloop.proxy.store import ProxyError, _now, _parse
from skillloop.proxy.task_admission import deployment_deadline
from skillloop.proxy.wire import validate_control


class EvaluatorTaskAdmission:
    def __init__(self, admission):
        if os.geteuid() != 21003:
            raise PermissionError('private_admission_actual_proxy')
        self.base, self.store = admission, admission.store
        with self.store._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS evaluator_admission_schema('
                'singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL)')
            version = db.execute('SELECT version FROM evaluator_admission_schema WHERE singleton=1').fetchone()
            if version is not None and version[0] != 1:
                raise ValueError('private_admission_schema_version')
            db.execute('CREATE TABLE IF NOT EXISTS evaluator_task_transports('
                       'transport TEXT PRIMARY KEY,intent TEXT UNIQUE NOT NULL,session TEXT UNIQUE NOT NULL,'
                       'request BLOB NOT NULL)')
            if [r[1] for r in db.execute('PRAGMA table_info(evaluator_task_transports)')] != ['transport','intent','session','request']:
                raise ValueError('private_admission_schema_shape')
            if version is None:
                if db.execute('SELECT 1 FROM evaluator_task_transports LIMIT 1').fetchone() is not None:
                    raise ValueError('private_admission_unversioned_existing_records')
                db.execute('INSERT INTO evaluator_admission_schema VALUES(1,1)')

    def committed_receipt(self, transport):
        with closing(self.store._connect()) as db:
            row = db.execute('SELECT a.receipt FROM evaluator_task_transports p '
                'JOIN controller_task_admissions a ON a.intent=p.intent WHERE p.transport=?', (transport,)).fetchone()
        return None if row is None else row[0]

    def admit(self, path, *, expected_digest=None):
        value = read_owned(path, uid=21004, gid=21003, limit=2097152)
        fields = {'kind', 'deployment_epoch', 'campaign_id', 'profile_id', 'domain', 'policy',
            'binding', 'run_request', 'run_deadline', 'config', 'source_admission', 'input_resources',
            'intent_digest', 'session_ref', 'development_plan_digest', 'digest'}
        if (set(value) != fields or value['kind'] != 'EvaluatorCurrentTaskAdmission'
                or value['deployment_epoch'] != self.store.deployment_epoch
                or (expected_digest is not None and value['digest'] != expected_digest)
                or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', value[k])
                       for k in ('intent_digest', 'session_ref', 'development_plan_digest'))):
            raise ValueError('private_admission_current_task_shape')
        campaign = value['campaign_id']; pins = self.base.campaigns.get(campaign)
        if pins is None or digest_jcs(value['config']) != pins['config_digest']:
            raise ProxyError('denied')
        request, binding = value['run_request'], value['binding']
        for obj, kind in ((request, 'RunRequest'), (binding, 'TaskBinding'),
                          (value['domain'], 'AuthorizationDomain'), (value['policy'], 'Policy')):
            validate_envelope(obj)
            if obj['kind'] != kind: raise ValueError('private_admission_envelope_kind')
        rb = request['body']
        if (rb['config_digest'] != pins['config_digest']
                or rb['subject_digest'] != binding['body']['subject_digest']
                or rb['authorization_domain_digest'] != value['domain']['digest']):
            raise ValueError('private_admission_request_binding')
        admission = value['source_admission']
        validate_source_admission(admission, value['config'], rb['subject_digest'])
        known = self.base._subject_pins(campaign).get(rb['subject_digest'])
        if (known is None or admission['source_snapshot']['digest'] != known['source_snapshot_digest']
                or digest_jcs(admission['manifest']) != known['skill_manifest_digest']
                or admission['approved_sources'] != {known['source_snapshot_digest']: known['skill_manifest_digest']}):
            raise ProxyError('denied')
        encoded = admission['package_files']; input_encoded = value['input_resources']
        if (type(encoded) is not dict or not 1 <= len(encoded) <= 32
                or any(type(v) is not str or len(v) > 5464 for v in encoded.values())
                or type(input_encoded) is not dict or not 1 <= len(input_encoded) <= 32
                or any(type(v) is not str or len(v) > 131072 for v in input_encoded.values())):
            raise ValueError('private_admission_current_bytes_capacity')
        package = {k: base64.b64decode(v, validate=True) for k, v in encoded.items()}
        inputs = {k: base64.b64decode(v, validate=True) for k, v in input_encoded.items()}
        loader = ApprovedPackageLoader(approved_sources=admission['approved_sources'],
            reference_resource_ids=admission['reference_resource_ids'], approved_subjects=admission.get('approved_subjects'))
        deadline = _parse(value['run_deadline'])
        task = binding['body']['task_instance_id']
        with self.store._transaction() as db:
            prior = db.execute('SELECT intent,session,request FROM evaluator_task_transports WHERE transport=?',
                               (value['digest'],)).fetchone()
            if prior is not None:
                if tuple(prior) != (value['intent_digest'], value['session_ref'], canonical_json_line(value)):
                    raise ValueError('private_admission_transport_conflict')
                row = db.execute('SELECT receipt FROM controller_task_admissions WHERE intent=?',
                                 (value['intent_digest'],)).fetchone()
                if row is None: raise RuntimeError('private_admission_committed_transport_without_task')
                from skillloop.protocol import decode_json
                return decode_json(row[0])
            deployment = db.execute('SELECT deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
            head = db.execute('SELECT plan FROM controller_plan_heads WHERE campaign=?', (campaign,)).fetchone()
            ttl = value['config'].get('proxy_deadline_seconds')
            if (deployment is None or deadline > deployment_deadline(deployment[0])
                    or type(ttl) is not int or not 1 <= ttl <= 300 or not 0 < (deadline - _now()).total_seconds() <= ttl):
                raise ProxyError('expired')
            if head is None or head[0] != value['development_plan_digest']:
                raise ProxyError('version_conflict')
            frozen = db.execute('SELECT development_plan,protected_plan FROM evaluator_protected_campaigns WHERE campaign=?',
                                (campaign,)).fetchone()
            if frozen is not None and tuple(frozen) != (head[0], rb['plan_digest']):
                raise ProxyError('version_conflict')
            grant = db.execute('SELECT admission_digest FROM controller_source_admissions WHERE campaign=? AND subject=?',
                               (campaign, rb['subject_digest'])).fetchone()
            if grant is None or grant[0] != digest_jcs(admission): raise ProxyError('denied')
            # Share the real campaign's 128-slot bound with development; the
            # opaque session cannot allocate a second slot for the same request.
            slot = digest_jcs({'subject': rb['subject_digest'], 'case': rb['case_digest'],
                               'repetition': rb['repetition_index'], 'phase': 'protected'})
            if db.execute('SELECT 1 FROM controller_task_slots WHERE campaign=? AND item=?', (campaign, slot)).fetchone():
                raise ProxyError('version_conflict')
            if db.execute('SELECT count(*) FROM controller_task_slots WHERE campaign=?', (campaign,)).fetchone()[0] >= 128:
                raise ProxyError('queue_full')
            issued = db.execute('SELECT role,method,result_json FROM operations WHERE operation_id=?',
                                (pins['approval_operation'],)).fetchone()
            if issued is None or tuple(issued[:2]) != ('admin', 'approve_domain'):
                raise ProxyError('approval_required')
            from skillloop.protocol import decode_json
            approval = decode_json(issued[2]); validate_control(approval)
            if approval['kind'] != 'ApprovalResult' or approval['body']['state'] != 'active':
                raise ProxyError('approval_required')
            approval_digest = approval['body']['approval_ref']
            self.store.stage_imported_task(loader=loader, source_snapshot=admission['source_snapshot'],
                package_files=package, skill_manifest=admission['manifest'], input_resources=inputs,
                domain=value['domain'], policy=value['policy'], binding=binding, run_request=request,
                profile_id=value['profile_id'], approval_digest=approval_digest,
                run_deadline=value['run_deadline'], campaign_id=campaign, _transaction_db=db)
            receipt = {'kind': 'EvaluatorCurrentTaskAdmissionReceipt', 'intent_digest': value['intent_digest'],
                'transport_digest': value['digest'], 'deployment_epoch': self.store.deployment_epoch,
                'campaign_id': campaign, 'run_request_digest': request['digest'], 'task_binding_digest': binding['digest'],
                'approval_digest': approval_digest, 'trust_revision': approval['body']['effective_trust_revision'],
                'producer_uid': 21003, 'qualification_issued': False}
            receipt['digest'] = digest_jcs(receipt)
            db.execute('INSERT INTO controller_task_slots VALUES(?,?,?)', (campaign, slot, task))
            db.execute('INSERT INTO controller_task_admissions VALUES(?,?,?)',
                       (value['intent_digest'], task, canonical_json_line(receipt)))
            db.execute('INSERT INTO evaluator_task_transports VALUES(?,?,?,?)',
                       (value['digest'], value['intent_digest'], value['session_ref'], canonical_json_line(value)))
            db.execute('INSERT OR IGNORE INTO evaluator_protected_campaigns VALUES(?,?,?)',
                       (campaign, head[0], rb['plan_digest']))
        return receipt
