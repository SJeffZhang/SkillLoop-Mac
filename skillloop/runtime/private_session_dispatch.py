"""Controller launches an Evaluator-owned sealed session without reading it.

Private assignments, results and logs remain in Evaluator custody. Process
completion is only transport evidence and cannot issue a qualification.
"""
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import stat

from skillloop.protocol import digest_jcs
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.repair.budget import SpendingLedger
from skillloop.ci.campaign_registry import CampaignRegistry


def resolve_session_policy(policy_path):
    """Resolve a dispatch digest from the current Evaluator opaque receipt."""
    if os.geteuid()!=21001:raise PermissionError('private_session_production_actual_controller')
    from skillloop.discovery.formal_task_gate import read_owned
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=2097152)
    if policy.get('kind')!='FrozenPrivateSessionProduction':return policy
    fields={'kind','image','campaign_deadline','campaign_digest','whole_round_manifest_digest',
        'maximum_evidence_bytes','timeout_seconds','keeper_id','mounts'}
    if (set(policy)!={'kind','stage','production_policy_digest','dispatch_template','action_reference_path','runtime_reference_path','digest'}
            or type(policy['dispatch_template']) is not dict or set(policy['dispatch_template'])!=fields):
        raise ValueError('private_session_production_frozen_recipe')
    template=policy['dispatch_template']
    action=read_owned(policy['action_reference_path'],uid=21004,gid=21001,limit=262144)
    reference=read_owned(policy['runtime_reference_path'],uid=21004,gid=21001,limit=262144)
    gate=template['kind']=='FrozenOpaquePrivateGateDispatch'
    if (template['kind'] not in {'FrozenOpaquePrivateGateDispatch','FrozenOpaquePrivateSessionDispatch'}
            or set(action)!={'kind','campaign_id','deployment_epoch','reference_digest','stage','policy_digest',
                'action_digest','assignment_filename','qualification_issued','digest'}
            or action.get('kind')!='EvaluatorOpaqueClosingAction'
            or action.get('stage')!=policy['stage']
            or action.get('policy_digest')!=policy['production_policy_digest']
            or policy['stage'] not in {'capture','evaluate','task_gate','session_complete','archive',
                'archive_gate','terminal_authority_snapshot','retirement_gate'}
            or action.get('qualification_issued') is not False
            or action.get('assignment_filename')!=('assignment.json' if policy['stage'] in {'task_gate','archive_gate'} else 'action.json')
            or action.get('campaign_id')!=template['campaign_digest']
            or action.get('reference_digest')!=reference['digest']
            or action.get('deployment_epoch')!=reference.get('deployment_epoch')
            or reference.get('campaign_id')!=template['campaign_digest']
            or reference.get('kind')!='EvaluatorOpaqueRunReference'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',action.get('action_digest',''))
            or gate!=(action.get('stage') in {'task_gate','archive_gate','retirement_gate'})):
        raise ValueError('private_session_production_current_action')
    resolved={**template,'action_digest':action['action_digest']}
    resolved['digest']=digest_jcs(resolved)
    return resolved


def _dispatch_session_under_scope(*,policy,journal_directory,engine,ledger,registry,whole_round_manifest_path,state,archive_mount_policy_path=None,archive_attestation_directory=None):
    if (os.geteuid() != 21001 or type(engine) is not DockerEngine
            or type(ledger) is not SpendingLedger or type(registry) is not CampaignRegistry):
        raise PermissionError('formal_session_dispatch_actual_controller')
    fields = {'kind', 'action_digest', 'image', 'campaign_deadline','campaign_digest',
              'whole_round_manifest_digest','maximum_evidence_bytes',
              'timeout_seconds', 'keeper_id', 'mounts', 'digest'}
    if (type(policy) is not dict or set(policy) != fields
            or policy['kind'] not in {'FrozenOpaquePrivateSessionDispatch','FrozenOpaquePrivateGateDispatch'}
            or policy['digest'] != digest_jcs({k:v for k,v in policy.items() if k != 'digest'})
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['action_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['image'])
            or not re.fullmatch(r'[0-9a-f]{64}', policy['keeper_id'])
            or type(policy['maximum_evidence_bytes']) is not int
            or not 1<=policy['maximum_evidence_bytes']<=(2149580800 if type(policy.get('mounts')) is dict and
                ({'archive','archive_output'} & set(policy['mounts'])) else 1074003968 if
                type(policy.get('mounts')) is dict and 'gate_authority' in policy['mounts'] else 20971520)
            or type(policy['timeout_seconds']) is not int
            or not 1 <= policy['timeout_seconds'] <= (300 if policy['kind']=='FrozenOpaquePrivateGateDispatch'
                or (type(policy.get('mounts')) is dict and ({'prepared_assignment','archive_output'} & set(policy['mounts']))) else 30)):
        raise ValueError('formal_session_frozen_opaque_dispatch')
    whole=read_round_manifest(whole_round_manifest_path)
    if (whole['digest']!=policy['whole_round_manifest_digest'] or whole['image']!=policy['image']
            or state['gate_freeze']['deadline']!=policy['campaign_deadline']
            or ledger.campaign_started_at is None
            or datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00')).timestamp()
                !=ledger.campaign_started_at+28800):
        raise ValueError('formal_session_original_whole_round_binding')
    deadline = datetime.fromisoformat(policy['campaign_deadline'].replace('Z', '+00:00'))
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds() <= policy['timeout_seconds']+120:
        raise TimeoutError('formal_session_original_clock')
    journal = Path(journal_directory)
    info = journal.lstat()
    if (not journal.is_absolute() or journal.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (21001, 21001, 0o700)
            or any(journal.iterdir())):
        raise PermissionError('formal_session_fresh_controller_journal')
    gate=policy['kind']=='FrozenOpaquePrivateGateDispatch'
    retirement_mounts={'assignment','private_authority','session_projection','private_completion','task_reviews','archive_reviews','retirement_grants'}
    archive_gate_mounts={'assignment','archive','original_reviews','reviews','archive_mount'}
    base_mounts = {'assignment', 'private', 'projection', 'evaluation', 'reviews', 'authority'}
    if (type(policy['mounts']) is not dict or set(policy['mounts']) not in
            (base_mounts, base_mounts | {'private_task_inbox', 'private_policy', 'tokenizer'},
             base_mounts | {'private_receipts', 'private_launch_inbox'},
             base_mounts | {'private_started', 'runtime_current'},
             base_mounts | {'gate_authority'},
             base_mounts | {'production_policy','current_reference','prepared_assignment','action_output','opaque_actions'},
             base_mounts | {'runtime_handoff','private_completion','private_raw','evaluation_assignment'},
             base_mounts | {'prepared_assignment','private_raw','task_snapshot','tokenizer'},
             base_mounts | {'prepared_assignment','private_raw','task_snapshot','archive_policy','archive_mount','archive_output'},
             {'assignment','runtime','snapshot','evaluation','reviews','tokenizer'},archive_gate_mounts,retirement_mounts)):
        raise ValueError('formal_session_dispatch_mount_set')
    retirement=gate and set(policy['mounts'])==retirement_mounts
    archive_gate=gate and set(policy['mounts'])==archive_gate_mounts
    if gate != (set(policy['mounts']) in ({'assignment','runtime','snapshot','evaluation','reviews','tokenizer'},archive_gate_mounts,retirement_mounts)):
        raise ValueError('formal_private_gate_exact_role_mounts')
    mounts = []
    targets = {'assignment':'/assignment', 'private':'/private',
               'projection':'/session-projection', 'evaluation':'/evaluation', 'reviews':'/reviews',
               'authority':'/authority-projection'}
    if 'private_task_inbox' in policy['mounts']:
        targets['private_task_inbox'] = '/private-task-inbox'
        targets['private_policy'] = '/private-policy'
        targets['tokenizer'] = '/model'
    if 'private_launch_inbox' in policy['mounts']:
        targets['private_receipts'] = '/private-receipts'
        targets['private_launch_inbox'] = '/private-launch-inbox'
    if 'private_started' in policy['mounts']:
        targets['private_started'] = '/private-started'
        targets['runtime_current'] = '/runtime-current'
    if 'gate_authority' in policy['mounts']:targets['gate_authority']='/gate-authority'
    if 'production_policy' in policy['mounts']:
        targets.update(production_policy='/production-policy',current_reference='/current-reference',
            prepared_assignment='/prepared-assignment',action_output='/action-output',opaque_actions='/opaque-actions')
    if 'runtime_handoff' in policy['mounts']:
        targets.update(runtime_handoff='/runtime-handoff',private_completion='/private-completion',
                       private_raw='/private-raw',evaluation_assignment='/evaluation-assignment')
    if 'prepared_assignment' in policy['mounts'] and 'production_policy' not in policy['mounts']:
        targets.update(prepared_assignment='/evaluation-assignment',private_raw='/private-raw',
                       task_snapshot='/authority')
        if 'tokenizer' in policy['mounts']:targets['tokenizer']='/model'
    if 'archive_output' in policy['mounts']:
        targets.update(archive_policy='/archive-policy',archive_mount='/archive-mount',archive_output='/archive')
    if gate:targets={'assignment':'/assignment','runtime':'/raw','snapshot':'/authority',
                     'evaluation':'/evaluation','reviews':'/reviews','tokenizer':'/model'}
    if archive_gate:targets={'assignment':'/assignment','archive':'/archive','original_reviews':'/original-reviews',
        'reviews':'/reviews','archive_mount':'/archive-mount'}
    if retirement:targets={'assignment':'/assignment','private_authority':'/private-authority',
        'session_projection':'/session-projection','private_completion':'/private-completion',
        'task_reviews':'/task-reviews','archive_reviews':'/archive-reviews','retirement_grants':'/retirement-grants'}
    for key, target in targets.items():
        pin = policy['mounts'][key]
        if type(pin) is not dict or set(pin) != {'volume','subpath'}:
            raise ValueError('formal_session_volume_pin')
        subpath = PurePosixPath(pin['subpath'])
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', pin['volume'])
                or not subpath.parts or subpath.is_absolute() or '..' in subpath.parts
                or str(subpath) != pin['subpath']):
            raise ValueError('formal_session_volume_subpath')
        mounts.append({'Type':'volume', 'Source':pin['volume'], 'Target':target,
            'ReadOnly':key not in ({'retirement_grants'} if retirement else {'reviews'} if gate else
                ({'private','projection','action_output','opaque_actions'} if 'production_policy' in policy['mounts'] else
                ({'private','projection','archive_output'} if 'archive_output' in policy['mounts'] else
                ({'private','projection','evaluation'} if 'prepared_assignment' in policy['mounts'] else
                {'private','projection','private_task_inbox','private_launch_inbox','runtime_current','gate_authority','private_raw','evaluation_assignment'})))),
            'VolumeOptions':{'Subpath':pin['subpath']}})
    from skillloop.runtime.role_deployment import private_role_configuration
    groups=(['21001','21004'] if gate else ['21001'])
    if {'private_task_inbox','private_receipts'} & set(policy['mounts']):groups.append('21003')
    if 'runtime_current' in policy['mounts']:groups.append('21002')
    if {'gate_authority','archive_output'} & set(policy['mounts']):groups.append('21005')
    config=private_role_configuration(entry='retirement_gate' if retirement else 'task_gate' if gate else 'session',
        image=policy['image'],deployment_epoch=whole['deployment_epoch'],action_digest=policy['action_digest'],
        mounts=mounts,groups=groups,maximum_bytes=policy['maximum_evidence_bytes'],timeout_seconds=policy['timeout_seconds'])
    def keeper():
        actual = engine.inspect(policy['keeper_id'])
        pin = policy['mounts']['private_authority' if retirement else 'archive' if archive_gate else 'runtime' if gate else 'private']
        matches = [m for m in actual.get('HostConfig',{}).get('Mounts',[])
            if m.get('Type') == 'volume' and m.get('Source') == pin['volume']
            and m.get('ReadOnly') is True
            and m.get('VolumeOptions',{}).get('Subpath') == pin['subpath']]
        if (actual.get('Id') != policy['keeper_id'] or actual.get('Image') != policy['image']
                or actual.get('Config',{}).get('User') != '21001:21001'
                or actual.get('State',{}).get('Running') is not True or len(matches) != 1):
            raise ValueError('formal_session_private_keeper_required')
        return actual
    _save(journal,'intent.json',{'kind':'OpaquePrivateSessionDispatchIntent',
        'configuration':config,'policy_digest':policy['digest'],'keeper':keeper(),
        'container_name':'skillloop-session-'+policy['action_digest'][7:39],'campaign_id':policy['campaign_digest'],
        'campaign_deadline':policy['campaign_deadline'],'started_at':datetime.now(timezone.utc).isoformat(),
        'reserved_seconds':policy['timeout_seconds']+60})
    spending=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='protected',
        operation_key='private-session-'+policy['action_digest'][7:],seconds=policy['timeout_seconds']+60,
        input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
    _save(journal,'spending.json',{'kind':'OpaquePrivateSessionSpending','spending':spending})
    try:
        identifier = engine.create('skillloop-session-'+policy['action_digest'][7:39],config)
        _save(journal,'created.json',{'kind':'PrivateSessionProcessCreated','container_id':identifier})
        initial=engine.inspect(identifier)
        _verify_role_process(initial,identifier,config,mounts)
        if initial.get('HostConfig',{}).get('LogConfig',{}).get('Type')!='none':
            raise ValueError('formal_session_private_logs_not_controller_visible')
        keeper()
        if 'archive_output' in policy['mounts']:
            from skillloop.discovery.formal_task_gate import read_owned
            from skillloop.runtime.task_archive import attest_private_archive_mount,resolve_private_archive_policy
            if archive_mount_policy_path is None or archive_attestation_directory is None:
                raise ValueError('private_archive_original_mount_attestation_required')
            archive_policy=resolve_private_archive_policy(read_owned(archive_mount_policy_path,uid=21010,gid=21001,limit=262144),
                action_digest=policy['action_digest'])
            if (archive_policy['controller_container_id']!='action-'+policy['action_digest']
                    or archive_policy['image']!=policy['image']
                    or archive_policy['archive_volume']!=policy['mounts']['archive_output']['volume']):
                raise ValueError('private_archive_actual_dispatch_mount_binding')
            attest_private_archive_mount(policy=archive_policy,engine=engine,output_directory=archive_attestation_directory,container_id=identifier)
        engine.start(identifier)
        wait = engine.wait(identifier,policy['timeout_seconds'])
        actual = engine.inspect(identifier)
        _verify_role_process(actual,identifier,config,mounts)
        if actual.get('HostConfig',{}).get('LogConfig',{}).get('Type') != 'none':
            raise ValueError('formal_session_private_logs_not_controller_visible')
        completion = {'kind':'OpaquePrivateSessionProcessCompletion',
            'action_digest':policy['action_digest'],'inspection':actual,'wait':wait,
            'keeper':keeper(),'qualification_issued':False,'private_result_verified':False}
        completion=_save(journal,'completion.json',completion)
        if actual['State']['Running'] or wait['StatusCode'] or actual['State']['ExitCode']:
            raise RuntimeError('formal_session_failed_private_custody_preserved')
        return completion
    except BaseException as error:
        try:
            from skillloop.runtime.private_process_preservation import preserve_original_private_process
            preserve_original_private_process(journal_directory=journal,dispatch='session',engine=engine,
                expected_campaign=policy['campaign_digest'],error_type=type(error).__name__)
        except BaseException as secondary:
            error.add_note('private_session_requires_recovery:'+type(secondary).__name__)
        raise


def recover_session_completion(*,journal_directory,engine,policy):
    """Reuse a successful original receipt; never repeat a session action."""
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('private_session_recovery_actual_controller')
    from skillloop.runtime.protected_flow import _controller_record
    from skillloop.runtime.private_process_preservation import preserve_original_private_process
    root=Path(journal_directory);intent=_controller_record(root/'intent.json')
    cost=_controller_record(root/'spending.json')
    if (intent.get('kind')!='OpaquePrivateSessionDispatchIntent'
            or intent.get('policy_digest')!=policy['digest']
            or cost.get('kind')!='OpaquePrivateSessionSpending'):
        raise ValueError('private_session_recovery_original_intent')
    if not os.path.lexists(root/'completion.json'):
        preserve_original_private_process(journal_directory=root,dispatch='session',engine=engine,
            expected_campaign=policy['campaign_digest'])
        return None
    result=_controller_record(root/'completion.json');created=_controller_record(root/'created.json')
    if (result.get('kind')!='OpaquePrivateSessionProcessCompletion'
            or result.get('action_digest')!=policy['action_digest']
            or created.get('kind')!='PrivateSessionProcessCreated'
            or result.get('inspection',{}).get('Id')!=created.get('container_id')
            or result.get('wait',{}).get('StatusCode')!=0):
        raise RuntimeError('private_session_recovery_failed_or_unknown_no_reexecution')
    actual=engine.inspect(created['container_id']);config=intent['configuration']
    _verify_role_process(actual,created['container_id'],config,config['HostConfig']['Mounts'])
    if (actual.get('State',{}).get('Running') is not False or actual.get('State',{}).get('ExitCode')!=0
            or actual.get('Config')!=result['inspection'].get('Config')):
        raise ValueError('private_session_recovery_original_process')
    keeper=engine.inspect(policy['keeper_id'])
    if (keeper.get('Id')!=result['keeper'].get('Id') or keeper.get('Image')!=policy['image']
            or keeper.get('Config')!=result['keeper'].get('Config')
            or keeper.get('HostConfig')!=result['keeper'].get('HostConfig')
            or keeper.get('State',{}).get('Running') is not True):
        raise RuntimeError('private_session_recovery_original_custody_required')
    return result


def dispatch_session_action(*,policy,journal_directory,engine,ledger,registry,whole_round_manifest_path,archive_mount_policy_path=None,archive_attestation_directory=None):
    if (os.geteuid()!=21001 or type(registry) is not CampaignRegistry
            or type(policy) is not dict or type(policy.get('campaign_digest')) is not str
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',policy['campaign_digest'])):
        raise PermissionError('formal_session_controller_frozen_registry_required')
    # Hold generation/subject fencing through actual Engine completion, not
    # merely preflight. A concurrent trigger cannot invalidate this handoff.
    with registry.private_scope(campaign=policy['campaign_digest']) as state:
        return _dispatch_session_under_scope(policy=policy,journal_directory=journal_directory,
            engine=engine,ledger=ledger,registry=registry,whole_round_manifest_path=whole_round_manifest_path,
            state=state,archive_mount_policy_path=archive_mount_policy_path,
            archive_attestation_directory=archive_attestation_directory)
