"""Controller dispatches an admitted private Runtime without reading its packet.

Only opaque references, actual Lease and container metadata are Controller data.
Runtime output/logs remain in the evidence volume for Evaluator and independent
Gate; process completion alone cannot release custody or issue a qualification.
"""
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import stat

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs, validate_envelope
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.task_controller import FormalTaskController
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.repair.budget import SpendingLedger
from skillloop.ci.campaign_registry import CampaignRegistry


def dispatch_private_runtime(*, policy_path, reference_path, started_path, journal_directory,
                             whole_round_manifest_path, engine, ledger, registry, controller):
    if (os.geteuid() != 21001 or type(engine) is not DockerEngine
            or type(ledger) is not SpendingLedger or type(registry) is not CampaignRegistry
            or type(controller) is not FormalTaskController):
        raise PermissionError('private_runtime_actual_controller_required')
    policy = read_owned(policy_path, uid=21010, gid=21001, limit=262144)
    fields = {'kind', 'campaign_id', 'deployment_epoch', 'image', 'whole_round_manifest_digest',
              'campaign_deadline', 'worker_seconds', 'keeper_id', 'mounts', 'handoff', 'digest'}
    if (set(policy) != fields or policy['kind'] != 'AdminOpaquePrivateRuntimeDispatch'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['image'])
            or not re.fullmatch(r'[0-9a-f]{64}', policy['keeper_id'])
            or type(policy['worker_seconds']) is not int or not 1 <= policy['worker_seconds'] <= 300):
        raise ValueError('private_runtime_admin_dispatch_policy')
    if controller.epoch != policy['deployment_epoch']:
        raise ValueError('private_runtime_controller_deployment')
    reference = read_owned(reference_path, uid=21004, gid=21001, limit=262144)
    started = read_owned(started_path, uid=21001, gid=21004, limit=262144)
    if (reference.get('kind') != 'EvaluatorOpaqueRunReference'
            or not re.fullmatch(r'private-run-[0-9a-f]{32}', reference.get('opaque_ref', ''))
            or started.get('kind') != 'OpaquePrivateRunStarted'
            or started.get('reference_digest') != reference['digest']
            or started.get('automatic_reexecution_allowed') is not False
            or any(reference.get(k) != policy[k] or started.get(k) != policy[k]
                   for k in ('campaign_id', 'deployment_epoch'))
            or any(started.get(k) != reference[k] for k in ('opaque_ref', 'approval_digest', 'trust_revision'))):
        raise ValueError('private_runtime_original_start_binding')
    lease = validate_envelope(started['lease'])
    expiry = datetime.fromisoformat(lease['body']['expires_at'].replace('Z', '+00:00'))
    original = datetime.fromisoformat(reference['run_deadline'].replace('Z', '+00:00'))
    deadline = datetime.fromisoformat(policy['campaign_deadline'].replace('Z', '+00:00'))
    whole = read_round_manifest(whole_round_manifest_path)
    scope = next((c for c in whole['campaigns'] if c['campaign_digest'] == policy['campaign_id']), None)
    if (scope is None or ledger.victim_seconds < policy['worker_seconds']
            or scope['victim_seconds'] != ledger.victim_seconds or whole['digest'] != policy['whole_round_manifest_digest'] or whole['image'] != policy['image']
            or whole['deployment_epoch'] != policy['deployment_epoch']
            or ledger.campaign_started_at is None or deadline.tzinfo is None
            or deadline.timestamp() != ledger.campaign_started_at + 28800
            or lease['kind'] != 'Lease' or lease['body']['state'] != 'active'
            or lease['body']['campaign_id'] != policy['campaign_id']
            or lease['body']['run_id'] != reference['run_id'] or lease['body']['fencing_token'] != 1
            or expiry.tzinfo is None or original.tzinfo is None or expiry > original
            or (expiry - datetime.now(timezone.utc)).total_seconds() <= policy['worker_seconds'] + 10
            or (deadline - datetime.now(timezone.utc)).total_seconds() <= policy['worker_seconds'] + 120):
        raise TimeoutError('private_runtime_original_lease_and_whole_budget')
    root = Path(journal_directory); info = root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (21001, 21001, 0o700)
            or any(root.iterdir())):
        raise PermissionError('private_runtime_fresh_controller_journal')
    targets = {'current': '/current', 'tokenizer': '/model', 'proxy': '/socket',
               'gateway': '/model-bridge', 'evidence': '/evidence'}
    if type(policy['mounts']) is not dict or set(policy['mounts']) != set(targets):
        raise ValueError('private_runtime_minimum_mount_set')
    mounts = []
    for key, target in targets.items():
        pin = policy['mounts'][key]
        if type(pin) is not dict or set(pin) != {'volume', 'subpath'}:
            raise ValueError('private_runtime_volume_pin')
        path = PurePosixPath(pin['subpath'])
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path) != pin['subpath']):
            raise ValueError('private_runtime_exact_subpath')
        mounts.append({'Type': 'volume', 'Source': pin['volume'], 'Target': target,
                       'ReadOnly': key != 'evidence', 'VolumeOptions': {'Subpath': pin['subpath']}})
    transfer=policy['handoff']
    if (type(transfer) is not dict or set(transfer)!=
            {'volume','subpath','maximum_bytes','maximum_files','timeout_seconds','completion_directory'}
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',transfer['volume'])
            or type(transfer['maximum_bytes']) is not int or not 1<=transfer['maximum_bytes']<=20971520
            or type(transfer['maximum_files']) is not int or not 1<=transfer['maximum_files']<=4096
            or type(transfer['timeout_seconds']) is not int or not 1<=transfer['timeout_seconds']<=60):
        raise ValueError('private_runtime_frozen_handoff_bounds')
    subpath=PurePosixPath(transfer['subpath'])
    if (not subpath.parts or subpath.is_absolute() or '..' in subpath.parts or str(subpath)!=transfer['subpath']):
        raise ValueError('private_runtime_handoff_volume_subpath')
    completion_directory=Path(transfer['completion_directory']);meta=completion_directory.lstat()
    if (not completion_directory.is_absolute() or completion_directory.is_symlink()
            or not stat.S_ISDIR(meta.st_mode)
            or (meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))!=(21001,21004,0o750)
            or 21004 not in set(os.getgroups())|{os.getegid()}):
        raise PermissionError('private_runtime_evaluator_completion_directory')
    config = {'Image': policy['image'], 'User': '21002:21002', 'Entrypoint': ['python'],
        'Cmd': ['/code/scripts/mac_agent_runtime.py'],
        'Env': ['PYTHONDONTWRITEBYTECODE=1', 'PYTHONPATH=/code/scripts/vendor:/code'],
        'Labels': {'skillloop.role': 'protected_runtime', 'skillloop.private_ref': reference['opaque_ref'],
                   'skillloop.run_request': reference['run_request_digest'],
                   'skillloop.deployment_epoch': policy['deployment_epoch']},
        'HostConfig': {'GroupAdd': [], 'NetworkMode': 'none', 'ReadonlyRootfs': True,
            'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'], 'Memory': 2147483648,
            'NanoCpus': 2000000000, 'PidsLimit': 128,
            'Ulimits': [{'Name': 'nofile', 'Soft': 128, 'Hard': 128}],
            'LogConfig': {'Type': 'none', 'Config': {}},
            'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=64m'}, 'Mounts': mounts}}

    def keeper():
        observed = engine.inspect(policy['keeper_id'])
        evidence = policy['mounts']['evidence']
        pinned = [m for m in observed.get('HostConfig', {}).get('Mounts', [])
                  if m.get('Type') == 'volume' and m.get('Source') == evidence['volume']
                  and m.get('ReadOnly') is True and m.get('VolumeOptions', {}).get('Subpath') == evidence['subpath']]
        if (observed.get('Id') != policy['keeper_id'] or observed.get('Image') != policy['image']
                or observed.get('Config', {}).get('User') != '21001:21001'
                or observed.get('Config', {}).get('Labels', {}).get('skillloop.run_request') != reference['run_request_digest']
                or observed.get('State', {}).get('Running') is not True or len(pinned) != 1):
            raise ValueError('private_runtime_original_evidence_keeper')
        return observed

    with registry.private_scope(campaign=policy['campaign_id']) as state:
        if state['gate_freeze']['deadline'] != policy['campaign_deadline']:
            raise ValueError('private_runtime_frozen_registry_scope')
        _save(root, 'intent.json', {'kind': 'OpaquePrivateRuntimeIntent', 'policy': policy,
              'reference': reference, 'started': started, 'configuration': config, 'keeper': keeper()})
        # Consumed before create: response loss and any initialized process stay
        # spent. An opaque key does not expose a private case/suite digest.
        spending = ledger.consume(reference['opaque_ref'], 0)
        _save(root, 'spending.json', {'kind': 'OpaquePrivateRuntimeSpending', 'spending': spending})
        identifier = engine.create('skillloop-' + reference['opaque_ref'], config)
        _save(root, 'created.json', {'kind': 'OpaquePrivateRuntimeCreated', 'container_id': identifier})
        try:
            actual = engine.inspect(identifier); _verify_role_process(actual, identifier, config, mounts)
            if actual['HostConfig'].get('LogConfig', {}).get('Type') != 'none':
                raise PermissionError('private_runtime_no_controller_logs')
            keeper()
            if (expiry - datetime.now(timezone.utc)).total_seconds() <= policy['worker_seconds']:
                raise TimeoutError('private_runtime_initialization_consumed_original_lease')
            engine.start(identifier)
            wait = engine.wait(identifier, policy['worker_seconds'])
            actual = engine.inspect(identifier); _verify_role_process(actual, identifier, config, mounts)
            if actual.get('State', {}).get('Running') or actual['HostConfig'].get('LogConfig', {}).get('Type') != 'none':
                raise ValueError('private_runtime_actual_terminal_state')
            closure = controller.finish_private_reference(reference, started, runtime_image=policy['image'],
                runtime_container_id=identifier, keeper_id=policy['keeper_id'],
                run_volume=policy['mounts']['evidence']['volume'], engine=engine)
            transfer_result=_dispatch_handoff(policy=policy,reference=reference,whole=whole,ledger=ledger,
                engine=engine,root=root,keeper=keeper)
            completion = {'kind': 'OpaquePrivateRuntimeCompletion', 'business_closure': closure,
                'handoff':transfer_result,'spending_state_digest':digest_jcs(spending), 'reference_digest': reference['digest'],
                'started_digest': started['digest'], 'inspection': actual, 'wait': wait, 'keeper': keeper(),
                'evidence_released': False, 'private_result_verified': False, 'qualification_issued': False}
            completion = _save(root, 'completion.json', completion)
            from skillloop.protection.current_task import _publish
            _publish(completion_directory/(reference['opaque_ref']+'.json'),completion,21004,handoff=True)
            # A failed worker is fenced too; its evidence remains for the
            # independent Evaluator/Gate to determine fail/inconclusive.
            return completion
        except BaseException as error:
            try:
                actual = engine.inspect(identifier); _verify_role_process(actual, identifier, config, mounts)
                if actual['State']['Running']:
                    engine.request('POST', '/containers/' + identifier + '/stop?t=1', timeout=5)
                _save(root, 'failure.json', {'kind': 'OpaquePrivateRuntimeFailure',
                    'container_id': identifier, 'reason_type': type(error).__name__,
                    'automatic_reexecution_allowed': False, 'evidence_released': False})
            except BaseException as secondary:
                error.add_note('private_runtime_requires_original_recovery:' + type(secondary).__name__)
            raise


def _dispatch_handoff(*,policy,reference,whole,ledger,engine,root,keeper):
    """Controller sees transport status only; no private archive/log reads."""
    transfer=policy['handoff'];deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if (deadline-datetime.now(timezone.utc)).total_seconds()<=transfer['timeout_seconds']+120:
        raise TimeoutError('private_handoff_original_remaining_clock')
    def volume(pin,target,readonly):
        return {'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':readonly,
                'VolumeOptions':{'Subpath':pin['subpath']}}
    mounts=[volume(policy['mounts']['current'],'/current',True),
            volume(policy['mounts']['evidence'],'/source-evidence',True),
            volume(transfer,'/handoff',False)]
    config={'Image':policy['image'],'User':'21002:21002','Entrypoint':['python'],
        'Cmd':['-m','skillloop.runtime.private_evidence_handoff'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
               'SKILLLOOP_HANDOFF_REQUEST='+reference['run_request_digest'],
               'SKILLLOOP_HANDOFF_BYTES='+str(transfer['maximum_bytes']),
               'SKILLLOOP_HANDOFF_FILES='+str(transfer['maximum_files']),
               'SKILLLOOP_HANDOFF_SECONDS='+str(transfer['timeout_seconds']),
               'SKILLLOOP_HANDOFF_DEADLINE='+policy['campaign_deadline']],
        'Labels':{'skillloop.role':'private_evidence_handoff','skillloop.private_ref':reference['opaque_ref']},
        'HostConfig':{'GroupAdd':['21004'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'LogConfig':{'Type':'none','Config':{}},'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    _save(root,'handoff-intent.json',{'kind':'OpaquePrivateHandoffIntent','configuration':config,'keeper':keeper()})
    cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_id'],stage='protected',
        operation_key=reference['opaque_ref']+'-evidence-handoff',seconds=transfer['timeout_seconds']+60,
        input_tokens=0,output_tokens=0,disk_bytes=transfer['maximum_bytes'])
    _save(root,'handoff-spending.json',{'kind':'OpaquePrivateHandoffSpending','spending':cost})
    identifier=engine.create('skillloop-handoff-'+reference['opaque_ref'],config)
    _save(root,'handoff-created.json',{'kind':'OpaquePrivateHandoffCreated','container_id':identifier})
    try:
        actual=engine.inspect(identifier);_verify_role_process(actual,identifier,config,mounts)
        if actual['HostConfig'].get('LogConfig',{}).get('Type')!='none':raise PermissionError('private_handoff_logs')
        keeper();engine.start(identifier);wait=engine.wait(identifier,transfer['timeout_seconds'])
        actual=engine.inspect(identifier);_verify_role_process(actual,identifier,config,mounts)
        result=_save(root,'handoff-completion.json',{'kind':'OpaquePrivateHandoffCompletion',
            'inspection':actual,'wait':wait,'keeper':keeper(),'private_bytes_verified':False,'evidence_released':False})
        if actual['State']['Running'] or wait['StatusCode'] or actual['State']['ExitCode']:
            raise RuntimeError('private_handoff_failed_original_evidence_preserved')
        return result
    except BaseException as error:
        try:
            actual=engine.inspect(identifier);_verify_role_process(actual,identifier,config,mounts)
            if actual['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            _save(root,'handoff-failure.json',{'kind':'OpaquePrivateHandoffFailure','container_id':identifier,
                'reason_type':type(error).__name__,'automatic_reexecution_allowed':False,'evidence_released':False})
        except BaseException as secondary:error.add_note('private_handoff_requires_recovery:'+type(secondary).__name__)
        raise
