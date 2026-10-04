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
    archive_gate_mounts={'assignment','archive','original_reviews','reviews'}
    base_mounts = {'assignment', 'private', 'projection', 'evaluation', 'reviews', 'authority'}
    if (type(policy['mounts']) is not dict or set(policy['mounts']) not in
            (base_mounts, base_mounts | {'private_task_inbox', 'private_policy', 'tokenizer'},
             base_mounts | {'private_receipts', 'private_launch_inbox'},
             base_mounts | {'private_started', 'runtime_current'},
             base_mounts | {'gate_authority'},
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
    if 'runtime_handoff' in policy['mounts']:
        targets.update(runtime_handoff='/runtime-handoff',private_completion='/private-completion',
                       private_raw='/private-raw',evaluation_assignment='/evaluation-assignment')
    if 'prepared_assignment' in policy['mounts']:
        targets.update(prepared_assignment='/evaluation-assignment',private_raw='/private-raw',
                       task_snapshot='/authority')
        if 'tokenizer' in policy['mounts']:targets['tokenizer']='/model'
    if 'archive_output' in policy['mounts']:
        targets.update(archive_policy='/archive-policy',archive_mount='/archive-mount',archive_output='/archive')
    if gate:targets={'assignment':'/assignment','runtime':'/raw','snapshot':'/authority',
                     'evaluation':'/evaluation','reviews':'/reviews','tokenizer':'/model'}
    if archive_gate:targets={'assignment':'/assignment','archive':'/archive','original_reviews':'/original-reviews','reviews':'/reviews'}
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
                ({'private','projection','archive_output'} if 'archive_output' in policy['mounts'] else
                ({'private','projection','evaluation'} if 'prepared_assignment' in policy['mounts'] else
                {'private','projection','private_task_inbox','private_launch_inbox','runtime_current','gate_authority','private_raw','evaluation_assignment'}))),
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
        'configuration':config,'policy_digest':policy['digest'],'keeper':keeper()})
    spending=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='protected',
        operation_key='private-session-'+policy['action_digest'][7:],seconds=policy['timeout_seconds']+60,
        input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
    _save(journal,'spending.json',{'kind':'OpaquePrivateSessionSpending','spending':spending})
    identifier = engine.create('skillloop-session-'+policy['action_digest'][7:39],config)
    _save(journal,'created.json',{'kind':'PrivateSessionProcessCreated','container_id':identifier})
    try:
        initial=engine.inspect(identifier)
        _verify_role_process(initial,identifier,config,mounts)
        if initial.get('HostConfig',{}).get('LogConfig',{}).get('Type')!='none':
            raise ValueError('formal_session_private_logs_not_controller_visible')
        keeper()
        if 'archive_output' in policy['mounts']:
            from skillloop.discovery.formal_task_gate import read_owned
            from skillloop.runtime.task_archive import attest_private_archive_mount
            if archive_mount_policy_path is None or archive_attestation_directory is None:
                raise ValueError('private_archive_original_mount_attestation_required')
            archive_policy=read_owned(archive_mount_policy_path,uid=21010,gid=21001,limit=262144)
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
        _save(journal,'completion.json',completion)
        if actual['State']['Running'] or wait['StatusCode'] or actual['State']['ExitCode']:
            raise RuntimeError('formal_session_failed_private_custody_preserved')
        return completion
    except BaseException as error:
        try:
            actual = engine.inspect(identifier)
            _verify_role_process(actual,identifier,config,mounts)
            if actual['State']['Running']:
                engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            _save(journal,'failure.json',{'kind':'PrivateSessionProcessFailure',
                'reason_type':type(error).__name__,'automatic_reexecution_allowed':False,
                'private_evidence_released':False})
        except BaseException as secondary:
            error.add_note('private_session_requires_recovery:'+type(secondary).__name__)
        raise


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
