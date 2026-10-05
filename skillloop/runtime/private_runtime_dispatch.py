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


def resolve_private_runtime_policy(policy_path,*,reference_path):
    if os.geteuid()!=21001:raise PermissionError('private_runtime_policy_actual_controller')
    declaration=read_owned(policy_path,uid=21010,gid=21001,limit=262144)
    if declaration.get('kind')!='FrozenPrivateRuntimeProduction':return declaration
    fields={'kind','campaign_id','deployment_epoch','image','whole_round_manifest_digest',
        'campaign_deadline','worker_seconds','mounts','handoff'}
    if (set(declaration)!={'kind','runtime_template','resource_journal','resource_policy_digest','digest'}
            or type(declaration['resource_journal']) is not str or not Path(declaration['resource_journal']).is_absolute()
            or '..' in Path(declaration['resource_journal']).parts
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',declaration['resource_policy_digest'])
            or type(declaration['runtime_template']) is not dict or set(declaration['runtime_template'])!=fields
            or declaration['runtime_template']['kind']!='FrozenOpaquePrivateRuntimeDispatch'
            or type(declaration['runtime_template']['mounts']) is not dict
            or set(declaration['runtime_template']['mounts'])!={'current','tokenizer','proxy','gateway'}):
        raise ValueError('private_runtime_original_production_template')
    from skillloop.runtime.protected_flow import _controller_record
    reference=read_owned(reference_path,uid=21004,gid=21001,limit=262144)
    resource=_controller_record(Path(declaration['resource_journal'])/'completion.json')
    template=declaration['runtime_template'];keeper=resource.get('keeper',{})
    if (resource.get('kind')!='PrivateRuntimeResourcesReady'
            or resource.get('policy_digest')!=declaration['resource_policy_digest']
            or resource.get('reference_digest')!=reference['digest']
            or resource.get('budget_closure')!='within_original_budget'
            or resource.get('keeper_alive_before_runtime_write') is not True
            or reference.get('campaign_id')!=template['campaign_id']
            or reference.get('deployment_epoch')!=template['deployment_epoch']
            or keeper.get('Image')!=template['image']
            or keeper.get('Config',{}).get('Labels',{}).get('skillloop.run_request')!=reference.get('run_request_digest')
            or resource.get('evidence_pin')!={'volume':resource.get('volume',{}).get('Name'),'subpath':None}):
        raise ValueError('private_runtime_actual_original_resources')
    policy={**template,'mounts':{**template['mounts'],'evidence':resource['evidence_pin']},'keeper_id':keeper['Id']}
    policy['digest']=digest_jcs(policy)
    return policy


def dispatch_private_runtime(*, policy_path, reference_path, started_path, journal_directory,
                             whole_round_manifest_path, engine, ledger, registry, controller):
    if (os.geteuid() != 21001 or type(engine) is not DockerEngine
            or type(ledger) is not SpendingLedger or type(registry) is not CampaignRegistry
            or type(controller) is not FormalTaskController):
        raise PermissionError('private_runtime_actual_controller_required')
    policy = resolve_private_runtime_policy(policy_path,reference_path=reference_path)
    fields = {'kind', 'campaign_id', 'deployment_epoch', 'image', 'whole_round_manifest_digest',
              'campaign_deadline', 'worker_seconds', 'keeper_id', 'mounts', 'handoff', 'digest'}
    if (set(policy) != fields or policy['kind'] not in {'AdminOpaquePrivateRuntimeDispatch','FrozenOpaquePrivateRuntimeDispatch'}
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
        whole_volume=key=='evidence' and pin['subpath'] is None
        path = PurePosixPath(pin['subpath']) if not whole_volume else None
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', pin['volume'])
                or not whole_volume and (not path.parts or path.is_absolute() or '..' in path.parts or str(path) != pin['subpath'])):
            raise ValueError('private_runtime_exact_subpath')
        mounts.append({'Type': 'volume', 'Source': pin['volume'], 'Target': target,
                       'ReadOnly': key != 'evidence', **({} if whole_volume else {'VolumeOptions': {'Subpath': pin['subpath']}})})
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
        if evidence['subpath'] is None:
            volume=engine.inspect_volume(evidence['volume'])
            labels=volume.get('Labels',{});options=volume.get('Options',{})
            match=re.fullmatch(r'size=([0-9]+),uid=21002,gid=21002,mode=0700',options.get('o',''))
            if (volume.get('Name')!=evidence['volume'] or volume.get('Driver')!='local'
                    or options.get('type')!='tmpfs' or options.get('device')!='tmpfs'
                    or match is None or not 1048576<=int(match[1])<=20971520
                    or labels.get('skillloop.run_request')!=reference['run_request_digest']
                    or labels.get('skillloop.deployment_epoch')!=policy['deployment_epoch']
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}',labels.get('skillloop.private_resource',''))
                    or observed.get('Config',{}).get('Labels',{}).get('skillloop.private_resource')!=labels['skillloop.private_resource']
                    or observed.get('Config',{}).get('Labels',{}).get('skillloop.role')!='private_evidence_keeper'):
                raise ValueError('private_runtime_independent_bounded_whole_volume')
        return observed

    with registry.private_scope(campaign=policy['campaign_id']) as state:
        if state['gate_freeze']['deadline'] != policy['campaign_deadline']:
            raise ValueError('private_runtime_frozen_registry_scope')
        _save(root, 'intent.json', {'kind': 'OpaquePrivateRuntimeIntent', 'policy': policy,
              'reference': reference, 'started': started, 'configuration': config, 'keeper': keeper(),
              'container_name':'skillloop-'+reference['opaque_ref'],'campaign_id':policy['campaign_id'],
              'campaign_deadline':policy['campaign_deadline'],'started_at':datetime.now(timezone.utc).isoformat(),
              'reserved_seconds':ledger.victim_seconds})
        # Consumed before create: response loss and any initialized process stay
        # spent. An opaque key does not expose a private case/suite digest.
        spending = ledger.consume(reference['opaque_ref'], 0)
        _save(root, 'spending.json', {'kind': 'OpaquePrivateRuntimeSpending', 'spending': spending})
        try:
            identifier = engine.create('skillloop-' + reference['opaque_ref'], config)
            _save(root, 'created.json', {'kind': 'OpaquePrivateRuntimeCreated', 'container_id': identifier})
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
                from skillloop.runtime.private_process_preservation import preserve_original_private_process
                preserve_original_private_process(journal_directory=root,dispatch='runtime',engine=engine,
                    expected_campaign=policy['campaign_id'],error_type=type(error).__name__)
            except BaseException as secondary:
                error.add_note('private_runtime_requires_original_recovery:' + type(secondary).__name__)
            raise



def recover_private_runtime_completion(*,journal_directory,engine,expected_campaign):
    """Recover an original committed transport receipt or contain uncertainty."""
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('private_runtime_recovery_actual_controller')
    from skillloop.runtime.protected_flow import _controller_record
    from skillloop.runtime.private_process_preservation import preserve_original_private_process
    from skillloop.protection.current_task import _publish
    root=Path(journal_directory)
    intent=_controller_record(root/'intent.json');cost=_controller_record(root/'spending.json')
    policy=intent['policy'];reference=intent['reference'];started=intent['started']
    if (intent.get('kind')!='OpaquePrivateRuntimeIntent' or cost.get('kind')!='OpaquePrivateRuntimeSpending'
            or policy.get('campaign_id')!=expected_campaign or reference.get('campaign_id')!=expected_campaign
            or started.get('reference_digest')!=reference['digest']):
        raise ValueError('private_runtime_recovery_original_binding')
    if not os.path.lexists(root/'completion.json'):
        failure=None
        try:
            if os.path.lexists(root/'handoff-spending.json'):
                preserve_original_private_process(journal_directory=root,dispatch='handoff',engine=engine,
                    expected_campaign=expected_campaign)
        except BaseException as error:failure=error
        try:
            preserve_original_private_process(journal_directory=root,dispatch='runtime',engine=engine,
                expected_campaign=expected_campaign)
        except BaseException as error:
            if failure is None:raise
            failure.add_note('private_runtime_preservation_unconfirmed:'+type(error).__name__)
        if failure is not None:raise failure
        return None
    completion=_controller_record(root/'completion.json');created=_controller_record(root/'created.json')
    if (created.get('kind')!='OpaquePrivateRuntimeCreated'
            or completion.get('kind')!='OpaquePrivateRuntimeCompletion'
            or completion.get('reference_digest')!=reference['digest']
            or completion.get('started_digest')!=started['digest']
            or completion.get('spending_state_digest')!=digest_jcs(cost['spending'])
            or completion.get('evidence_released') is not False):
        raise ValueError('private_runtime_recovery_original_completion')
    actual=engine.inspect(created['container_id']);config=intent['configuration']
    _verify_role_process(actual,created['container_id'],config,config['HostConfig']['Mounts'])
    if (actual.get('State',{}).get('Running') is not False
            or actual.get('State',{}).get('ExitCode')!=completion['wait']['StatusCode']
            or completion['inspection'].get('Id')!=actual['Id']
            or completion['inspection'].get('Config')!=actual['Config']):
        raise ValueError('private_runtime_recovery_original_terminal_process')
    handoff=_controller_record(root/'handoff-completion.json')
    handoff_intent=_controller_record(root/'handoff-intent.json')
    if (handoff!=completion.get('handoff') or handoff.get('kind')!='OpaquePrivateHandoffCompletion'
            or handoff.get('wait',{}).get('StatusCode')!=0):
        raise ValueError('private_runtime_recovery_original_handoff')
    helper=engine.inspect(handoff['inspection']['Id']);hconfig=handoff_intent['configuration']
    _verify_role_process(helper,handoff['inspection']['Id'],hconfig,hconfig['HostConfig']['Mounts'])
    if helper.get('State',{}).get('Running') is not False or helper.get('State',{}).get('ExitCode')!=0:
        raise ValueError('private_runtime_recovery_original_handoff_process')
    keeper=engine.inspect(policy['keeper_id'])
    if (keeper.get('Id')!=completion['keeper'].get('Id')
            or keeper.get('Config')!=completion['keeper'].get('Config')
            or keeper.get('HostConfig')!=completion['keeper'].get('HostConfig')
            or keeper.get('Image')!=policy['image']
            or keeper.get('State',{}).get('Running') is not True):
        raise RuntimeError('private_runtime_recovery_original_custody_required')
    # Lost publication may finish the same metadata handoff, never Runtime work.
    from skillloop.protection.current_task import _directory
    directory=_directory(policy['handoff']['completion_directory'],21001,21004,0o750)
    path=directory/(reference['opaque_ref']+'.json')
    if os.path.lexists(path):
        if read_owned(path,uid=21001,gid=21004,limit=8388608)!=completion:
            raise ValueError('private_runtime_recovery_published_completion_conflict')
    else:_publish(path,completion,21004,handoff=True)
    return completion


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
    _save(root,'handoff-intent.json',{'kind':'OpaquePrivateHandoffIntent','configuration':config,'keeper':keeper(),
        'container_name':'skillloop-handoff-'+reference['opaque_ref'],'campaign_id':policy['campaign_id'],
        'campaign_deadline':policy['campaign_deadline'],'started_at':datetime.now(timezone.utc).isoformat(),
        'reserved_seconds':transfer['timeout_seconds']+60})
    cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_id'],stage='protected',
        operation_key=reference['opaque_ref']+'-evidence-handoff',seconds=transfer['timeout_seconds']+60,
        input_tokens=0,output_tokens=0,disk_bytes=transfer['maximum_bytes'])
    _save(root,'handoff-spending.json',{'kind':'OpaquePrivateHandoffSpending','spending':cost})
    try:
        identifier=engine.create('skillloop-handoff-'+reference['opaque_ref'],config)
        _save(root,'handoff-created.json',{'kind':'OpaquePrivateHandoffCreated','container_id':identifier})
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
            from skillloop.runtime.private_process_preservation import preserve_original_private_process
            preserve_original_private_process(journal_directory=root,dispatch='handoff',engine=engine,
                expected_campaign=policy['campaign_id'],error_type=type(error).__name__)
        except BaseException as secondary:error.add_note('private_handoff_requires_recovery:'+type(secondary).__name__)
        raise
