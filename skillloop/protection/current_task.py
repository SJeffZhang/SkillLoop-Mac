"""Evaluator-owned current-task production from the committed private factory.

Full assignments remain private. The Proxy handoff omits the suite, plan,
objectives, mutations, expected output and all future tasks. Delivery is
committed before publishing that handoff; an interrupted handoff is not retried.
"""
import base64
from dataclasses import asdict
import os
from pathlib import Path
import re
import stat

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.loader import ApprovedPackageLoader, validate_source_admission
from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import canonical_json_line, digest_bytes, digest_jcs
from skillloop.runtime.task_controller import imported_task_intent
from skillloop.proxy.qualification_authority import current_authority


def _directory(path, uid, gid, mode):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode)):
        raise PermissionError('private_current_task_directory')
    return path


def _publish(path, value, gid, *, handoff=False):
    raw = canonical_json_line(value)
    if len(raw) > (2097152 if handoff else 8388608):
        raise ValueError('private_current_task_capacity')
    temporary = path.with_suffix('.pending') if handoff else path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), -1, gid)
        os.fchmod(stream.fileno(), 0o640)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if handoff:
        # The SQLite session reservation excludes a second legitimate producer
        # for this key. Publish with one link: the consumer must never observe
        # a transient two-link file and mistake it for a custody violation.
        if os.path.lexists(path):
            raise FileExistsError('private_current_task_handoff_exists')
        os.rename(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def prepare_and_deliver(*, authority, action_path, policy_path, lifecycle_review_path,
                        private_directory, proxy_inbox, authority_directory, tokenizer_directory):
    if os.geteuid() != 21004 or authority.readonly:
        raise PermissionError('private_current_task_actual_evaluator')
    action = read_owned(action_path, uid=21004, gid=21004, limit=262144)
    if (set(action) != {'kind', 'campaign_id', 'opaque_ref', 'item_id', 'digest'}
            or action['kind'] != 'FormalPrivateTaskPreparation'):
        raise ValueError('private_current_task_action')
    record = authority.resolve_formal_bundle(campaign=action['campaign_id'], opaque_ref=action['opaque_ref'])
    policy = read_owned(policy_path, uid=21010, gid=21004, limit=8388608)
    if (set(policy) != {'kind', 'campaign_id', 'deployment_epoch', 'config_digest',
                       'domain', 'policy', 'sources', 'digest'}
            or policy['kind'] != 'AdminPrivateCurrentTaskPolicy'
            or any(policy[k] != record[k] for k in ('campaign_id', 'deployment_epoch', 'config_digest'))
            or set(policy['sources']) != set(record['subjects'].values())):
        raise ValueError('private_current_task_admin_scope')
    lifecycle = read_owned(lifecycle_review_path, uid=21005, gid=21004, limit=262144)
    # A backend tags/version response and an arbitrary nonempty digest are
    # insufficient. Only an independently reviewed actual lifecycle is accepted.
    if (lifecycle.get('kind') != 'GatePrivateModelLifecycleReview'
            or any(lifecycle.get(k) != record[k] for k in
                   ('campaign_id', 'deployment_epoch', 'config_digest', 'source_index_digest'))
            or lifecycle.get('factory_epoch_id') != record['bundle']['epoch_id']
            or lifecycle.get('isolation_verified') is not True
            or lifecycle.get('development_backend_stopped') is not True
            or lifecycle.get('private_backend_fresh') is not True
            or not lifecycle.get('development_stop_evidence_digest')
            or not lifecycle.get('private_start_evidence_digest')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', record['config'].get('model_manifest_digest', ''))
            or lifecycle.get('model_manifest_digest') != record['config'].get('model_manifest_digest')
            or lifecycle.get('tokenizer_hashes') != record['config']['tokenizer_hashes']):
        raise ValueError('private_current_task_actual_backend_lifecycle_required')
    items = [i for i in record['private_plan']['body']['items']
             if i['item_id'] == action['item_id'] and i['phase'] == 'protected' and i['requirement'] == 'required']
    if len(items) != 1:
        raise ValueError('private_current_task_required_item')
    item = items[0]
    cases = [(name, c) for name, c in record['compiled']['cases'].items() if c['digest'] == item['case_digest']]
    if len(cases) != 1:
        raise ValueError('private_current_task_committed_case')
    private = _directory(private_directory, 21004, 21004, 0o750)
    inbox = _directory(proxy_inbox, 21004, 21003, 0o750)
    if 21003 not in set(os.getgroups()) | {os.getegid()}:
        raise PermissionError('private_current_task_proxy_read_group')
    admission = policy['sources'][item['subject_digest']]
    validate_source_admission(admission, record['config'], item['subject_digest'])
    package = {p: base64.b64decode(raw, validate=True) for p, raw in admission['package_files'].items()}
    loader = ApprovedPackageLoader(approved_sources=admission['approved_sources'],
        reference_resource_ids=admission['reference_resource_ids'], approved_subjects=admission.get('approved_subjects'))
    profile = record['compiled']['profile_id']
    selection = loader.select(admission['source_snapshot'], package, admission['manifest'],
        profile_id=profile, family_id=FamilyRegistry().profile(profile)['family_id'])
    inputs = {name: base64.b64decode(raw['base64_bytes'], validate=True) for name, raw in record['bundle']['inputs'].items()}
    expected = base64.b64decode(record['bundle']['expected_bytes']['base64_bytes'], validate=True)
    # Complete expensive tokenizer initialization and current payload rendering
    # before creating the short-lived business intent, never after its Lease.
    from skillloop.runtime.gateway import ExactLocalTokenizer
    from skillloop.discovery.mutation import compile_mutation
    tokenizer = ExactLocalTokenizer(tokenizer_directory, expected_hashes=record['config']['tokenizer_hashes'])
    try:
        spec = record['compiled']['mutations'].get(cases[0][0])
        notes = FamilyRegistry().profile(profile)['input_bindings']['notes']
        rendered = (compile_mutation(spec, source_bytes=inputs[notes], profile_id=profile,
                                    count_tokens=tokenizer.count_text) if spec else None)
        materials = {'mutation': None if rendered is None else asdict(rendered),
            'package_resources': {'instruction': selection.files[0][1],
                                  'references': [row[1] for row in selection.files[1:]]},
            'tokenizer_hashes': tokenizer.snapshot_hashes,
            'model_lifecycle_digest': lifecycle['digest']}
    finally:
        tokenizer.close()
    entry = {'kind': 'protected', 'entry_id': item['item_id'], 'profile': profile,
        'case_id': cases[0][0], 'repetition': item['repetition_index'], 'role': item['subject_role'],
        'config': record['config'], 'campaign_id': record['campaign_id'], 'epoch_id': record['bundle']['epoch_id'],
        'compiled': {**record['compiled'], 'subject_digest': selection.subject_digest,
                     'skill_digest': digest_bytes(package['SKILL.md'])},
        'plan': record['private_plan'], 'source_index_digest': record['source_index_digest'],
        'source_admission': admission, 'approval_factory_digest': record['factory_profile_digest'],
        'private_inputs': {name: base64.b64encode(raw).decode('ascii') for name, raw in inputs.items()},
        'private_expected_digest': digest_bytes(expected), 'model_lifecycle_digest': lifecycle['digest'],
        'development_epoch': record['deployment_epoch'],
        'development_suite_epoch_id': record['development_suite_epoch_id']}
    entry['digest'] = digest_jcs(entry)
    with current_authority(authority_directory, epoch=record['deployment_epoch'],
            config_digest=record['config_digest'], trust_revision=record['trust_revision'],
            approval_digests=set(record['approval_digests'])) as live:
        heads = [h for h in live.get('plan_heads', []) if h['campaign_id'] == record['campaign_id']]
        if len(heads) != 1 or heads[0]['plan_digest'] != record['development_plan_digest']:
            raise ValueError('private_current_task_development_head_changed')
        intent = imported_task_intent(entry, domain=policy['domain'], policy=policy['policy'],
                                      inputs=inputs, run_deadline=record['deadline'])
        # Validate the entire transport before the irreversible delivered mark.
        handoff = {k: intent[k] for k in ('deployment_epoch', 'campaign_id', 'profile_id',
            'domain', 'policy', 'binding', 'run_request', 'run_deadline', 'config', 'source_admission', 'input_resources')}
        assignment = {'kind': 'FormalPrivateDeliveryAssignment', 'entry': entry, 'intent': intent,
                      'campaign_deadline': record['deadline'], 'runtime_materials': materials}
        assignment['digest'] = digest_jcs(assignment)
        # The reserved session reference and digests are fixed-width strings.
        preview = {**handoff, 'kind': 'EvaluatorCurrentTaskAdmission', 'intent_digest': intent['digest'],
                   'session_ref': 'sha256:' + '0' * 64,
                   'development_plan_digest': record['development_plan_digest']}
        preview['digest'] = digest_jcs(preview)
        if len(canonical_json_line(preview)) > 2097152 or len(canonical_json_line(assignment)) > 8388608:
            raise ValueError('private_current_task_capacity_before_delivery')
        key = authority.reserve_formal_session(campaign=record['campaign_id'], private_record_digest=record['digest'],
            subject=item['subject_digest'], case=item['case_digest'], repetition=item['repetition_index'])
        path = private / (key[7:] + '.json')
        _publish(path, assignment, 21004)
        delivered = authority.deliver_formal_session(key=key, assignment_path=path)
        handoff.update(kind='EvaluatorCurrentTaskAdmission', intent_digest=intent['digest'],
            session_ref=key, development_plan_digest=record['development_plan_digest'])
        handoff['digest'] = digest_jcs(handoff)
        _publish(inbox / (handoff['digest'][7:] + '.json'), handoff, 21003, handoff=True)
        return {'kind': 'PrivateCurrentTaskPrepared', 'session_key': key, 'entry_digest': entry['digest'],
                'intent_digest': intent['digest'], 'handoff_digest': handoff['digest'],
                'delivery': delivered, 'qualification_issued': False}


def prepare_launch_reference(*, authority, action, projection_directory, receipt_directory,
                             private_directory, controller_inbox):
    """After real Proxy admission, expose only opaque run references to Controller."""
    import secrets
    if (os.geteuid() != 21004 or authority.readonly or set(action) !=
            {'kind', 'preparation_digest', 'campaign_id', 'digest'}
            or action['kind'] != 'FormalPrivateLaunchPreparation'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', action['preparation_digest'])):
        raise PermissionError('private_launch_actual_evaluator_action')
    projection = _directory(projection_directory, 21004, 21004, 0o750)
    prepared = read_owned(projection / (action['preparation_digest'][7:] + '.json'),
                          uid=21004, gid=21004, limit=262144)
    if (prepared.get('kind') != 'PrivateCurrentTaskPrepared'
            or prepared.get('action_digest') != action['preparation_digest']
            or prepared.get('delivery', {}).get('state') != 'delivered'):
        raise ValueError('private_launch_committed_preparation')
    pins = authority.formal_session_identity(prepared['session_key'])
    if (pins['campaign'] != action['campaign_id'] or pins.get('intent_digest') != prepared['intent_digest']):
        raise ValueError('private_launch_committed_session_identity')
    assignment = read_owned(Path(private_directory) / (prepared['session_key'][7:] + '.json'),
                            uid=21004, gid=21004, limit=8388608)
    intent = assignment['intent']
    receipt = read_owned(Path(receipt_directory) / (prepared['handoff_digest'][7:] + '.json'),
                         uid=21003, gid=21004, limit=262144)
    if (receipt.get('kind') != 'TaskAdmissionTransportReceipt' or receipt.get('ok') is not True
            or receipt.get('intent_digest') != prepared['handoff_digest']
            or receipt.get('deployment_epoch') != intent['deployment_epoch']):
        raise ValueError('private_launch_real_proxy_admission_required')
    accepted = receipt['result']
    if (accepted.get('kind') != 'EvaluatorCurrentTaskAdmissionReceipt'
            or accepted.get('digest') != digest_jcs({k: v for k, v in accepted.items() if k != 'digest'})
            or accepted.get('intent_digest') != intent['digest']
            or accepted.get('transport_digest') != prepared['handoff_digest']
            or accepted.get('producer_uid') != 21003
            or accepted.get('campaign_id') != action['campaign_id']
            or accepted.get('run_request_digest') != intent['run_request']['digest']
            or accepted.get('task_binding_digest') != intent['binding']['digest']):
        raise ValueError('private_launch_proxy_current_task_binding')
    from datetime import datetime, timezone
    expiry = datetime.fromisoformat(intent['run_deadline'].replace('Z', '+00:00'))
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise TimeoutError('private_launch_current_task_expired')
    inbox = _directory(controller_inbox, 21004, 21001, 0o750)
    ref = 'private-run-' + secrets.token_hex(16)
    launch = {'kind': 'EvaluatorOpaqueRunReference', 'opaque_ref': ref,
        'campaign_id': action['campaign_id'], 'deployment_epoch': intent['deployment_epoch'],
        'run_request_digest': accepted['run_request_digest'], 'task_binding_digest': accepted['task_binding_digest'],
        'run_deadline': intent['run_deadline'], 'run_id': intent['binding']['body']['run_id'],
        'approval_digest': accepted['approval_digest'],
        'trust_revision': accepted['trust_revision']}
    launch['digest'] = digest_jcs(launch)
    private_receipt = {'kind': 'PrivateRunLaunchMapping', 'action_digest': action['digest'],
        'session_key': prepared['session_key'], 'intent_digest': intent['digest'], 'launch': launch,
        'proxy_receipt_digest': receipt['digest'], 'qualification_issued': False}
    private_receipt['digest'] = digest_jcs(private_receipt)
    # Persist the private association first. A crash never constructs a second
    # randomized reference or starts the same delivered task again.
    authority.claim_formal_launch(key=prepared['session_key'], action_digest=action['digest'], reference=launch)
    _publish(projection / (action['digest'][7:] + '.launch.json'), private_receipt, 21004)
    _publish(inbox / (ref + '.json'), launch, 21001, handoff=True)
    return private_receipt


def prepare_runtime_request(*, authority, action, projection_directory, private_directory,
                            started_directory, runtime_directory, authority_directory):
    """Issue one current Runtime packet from the original delivered task/Lease.

    No full assignment, future cases or private result matrix leaves Evaluator.
    Exclusive publication preserves unknown sends without constructing a retry.
    """
    from datetime import datetime, timezone
    from skillloop.protocol import validate_envelope
    if (os.geteuid() != 21004 or authority.readonly or set(action) !=
            {'kind', 'campaign_id', 'launch_action_digest', 'digest'}
            or action['kind'] != 'FormalPrivateRuntimePreparation'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', action['launch_action_digest'])):
        raise PermissionError('private_runtime_actual_evaluator_action')
    projection = _directory(projection_directory, 21004, 21004, 0o750)
    mapping = read_owned(projection / (action['launch_action_digest'][7:] + '.launch.json'),
                         uid=21004, gid=21004, limit=262144)
    if mapping.get('kind') != 'PrivateRunLaunchMapping' or mapping.get('action_digest') != action['launch_action_digest']:
        raise ValueError('private_runtime_original_launch_mapping')
    launch = mapping['launch']
    pins = authority.formal_session_identity(mapping['session_key'])
    assignment = read_owned(Path(private_directory) / (mapping['session_key'][7:] + '.json'),
                            uid=21004, gid=21004, limit=8388608)
    intent = assignment['intent']
    if (pins['campaign'] != action['campaign_id'] or launch['campaign_id'] != pins['campaign']
            or pins.get('intent_digest') != intent['digest'] or mapping['intent_digest'] != intent['digest']
            or pins.get('entry_digest') != assignment['entry']['digest']):
        raise ValueError('private_runtime_delivered_assignment_binding')
    started = read_owned(Path(started_directory) / (launch['opaque_ref'] + '.json'),
                         uid=21001, gid=21004, limit=262144)
    if (started.get('kind') != 'OpaquePrivateRunStarted'
            or started.get('reference_digest') != launch['digest']
            or any(started.get(k) != launch[k] for k in
                   ('opaque_ref', 'campaign_id', 'deployment_epoch', 'approval_digest', 'trust_revision'))
            or started.get('automatic_reexecution_allowed') is not False):
        raise ValueError('private_runtime_actual_controller_start')
    lease = validate_envelope(started['lease'])
    config = intent['config']
    expiry = datetime.fromisoformat(lease['body']['expires_at'].replace('Z', '+00:00'))
    original_expiry = datetime.fromisoformat(intent['run_deadline'].replace('Z', '+00:00'))
    seconds = config.get('worker_deadline_seconds')
    if (lease['kind'] != 'Lease' or lease['body']['state'] != 'active'
            or lease['body']['campaign_id'] != intent['campaign_id']
            or lease['body']['run_id'] != intent['binding']['body']['run_id']
            or lease['body']['fencing_token'] != 1 or expiry.tzinfo is None
            or expiry > original_expiry or type(seconds) is not int or not 1 <= seconds <= 300
            or (expiry - datetime.now(timezone.utc)).total_seconds() <= seconds + 10):
        raise TimeoutError('private_runtime_original_lease_window')
    materials = assignment['runtime_materials']
    if (set(materials) != {'mutation', 'package_resources', 'tokenizer_hashes', 'model_lifecycle_digest'}
            or materials['tokenizer_hashes'] != config['tokenizer_hashes']
            or materials['model_lifecycle_digest'] != assignment['entry']['model_lifecycle_digest']):
        raise ValueError('private_runtime_prepared_materials_identity')
    target = _directory(runtime_directory, 21004, 21002, 0o750)
    if 21002 not in set(os.getgroups()) | {os.getegid()}:
        raise PermissionError('private_runtime_current_read_group')
    with current_authority(authority_directory, epoch=intent['deployment_epoch'],
            config_digest=digest_jcs(config), trust_revision=started['trust_revision'],
            approval_digests={started['approval_digest']}) as live:
        heads = [h for h in live.get('plan_heads', []) if h['campaign_id'] == intent['campaign_id']]
        with authority.connect() as db:
            row = db.execute('SELECT record FROM formal_private_bundles WHERE campaign=?', (pins['campaign'],)).fetchone()
        from skillloop.protocol import decode_json
        original = decode_json(row[0]) if row is not None else {}
        if (original.get('digest') != pins['private_record_digest']
                or original.get('digest') != digest_jcs({k:v for k,v in original.items() if k!='digest'})
                or len(heads) != 1 or heads[0]['plan_digest'] != original.get('development_plan_digest')):
            raise ValueError('private_runtime_frozen_development_head')
        packet = {'kind': 'FormalPrivateCurrentRuntimeRequest', 'profile': intent['profile_id'],
            'skill': None, 'request': intent['run_request'], 'binding': intent['binding'], 'config': config,
            'mutation': materials['mutation'], 'attempt': 0, 'deployment': intent['deployment_epoch'],
            'proxy_server_uid': 21003, 'run_lease': lease, 'trust_revision': started['trust_revision'],
            'package_resources': materials['package_resources'],
            'model_lifecycle_digest': materials['model_lifecycle_digest']}
        packet['digest'] = digest_jcs(packet)
        if len(canonical_json_line(packet)) > 2097152:
            raise ValueError('private_runtime_packet_capacity_before_publication')
        receipt = {'kind': 'PrivateRuntimePacketPrepared', 'action_digest': action['digest'],
            'session_key': mapping['session_key'], 'intent_digest': intent['digest'],
            'request_digest': packet['digest'], 'start_digest': started['digest'],
            'automatic_reexecution_allowed': False, 'qualification_issued': False}
        receipt['digest'] = digest_jcs(receipt)
        # Record the attempt before exposing the immutable current task.
        authority.claim_formal_runtime(key=mapping['session_key'], launch_action=action['launch_action_digest'],
            reference=launch, runtime_action=action['digest'])
        _publish(projection / (action['digest'][7:] + '.runtime.json'), receipt, 21004)
        _publish(target / 'current-request.json', packet, 21002, handoff=True)
        return receipt
