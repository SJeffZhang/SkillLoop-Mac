"""Actual Controller dispatch for Admin key custody and Gate encryption/review.

Policies carry opaque roots and immutable image/mount pins. Controller never
opens private inventory, ciphertext receipts or unwrapped data keys.
"""
from datetime import datetime,timezone
import os
from pathlib import Path,PurePosixPath
import re
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory
from skillloop.protocol import digest_jcs
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest


def dispatch_archive_action(*,policy_path,journal_directory,whole_round_manifest_path,ledger,engine):
    if os.geteuid()!=21001 or type(engine) is not DockerEngine or type(ledger) is not SpendingLedger:
        raise PermissionError('archive_dispatch_original_controller')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=2097152)
    fields={'kind','action','campaign','deployment_epoch','image','whole_round_manifest_digest',
        'deadline','operation_ref','worker_policy_digest','timeout_seconds','closure_seconds',
        'maximum_evidence_bytes','mounts','result_path','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenArchiveRoleDispatch'
            or policy['action'] not in {'key_service','export','review'}
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=1200
            or type(policy['closure_seconds']) is not int or not 30<=policy['closure_seconds']<=120
            or type(policy['maximum_evidence_bytes']) is not int or not 1<=policy['maximum_evidence_bytes']<=2147483648
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',policy['operation_ref'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',policy['worker_policy_digest'])):
        raise ValueError('archive_dispatch_full_frozen_budget')
    whole=read_round_manifest(whole_round_manifest_path)
    deadline=datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'))
    if (policy['whole_round_manifest_digest']!=whole['digest'] or policy['image']!=whole['image']
            or policy['deployment_epoch']!=whole['deployment_epoch']
            or not any(c['campaign_digest']==policy['campaign'] for c in whole['campaigns'])
            or deadline.tzinfo is None or ledger.campaign_started_at is None
            or deadline.timestamp()!=ledger.campaign_started_at+28800
            or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+policy['closure_seconds']):
        raise ValueError('archive_dispatch_original_source_clock')
    key_service=policy['action']=='key_service';uid=21010 if key_service else 21005
    targets=({'policy':'/archive-policy','crypto_lock':'/crypto-lock','keys':'/archive-keys',
        'public_key':'/archive-public','key_socket':'/archive-sockets','public_result':'/public-result'} if key_service else
        {'policy':'/archive-policy','crypto_lock':'/crypto-lock','public_key':'/archive-public',
         'key_socket':'/archive-sockets','encrypted':'/encrypted','private_result':'/private-result','public_result':'/public-result'})
    if type(policy['mounts']) is not dict:raise ValueError('archive_dispatch_fixed_mounts')
    if key_service and set(policy['mounts'])!=set(targets):raise ValueError('archive_key_no_private_evidence_mount')
    if not key_service:
        extras=set(policy['mounts'])-set(targets)
        if not 1<=len(extras)<=32 or any(not re.fullmatch(r'source-[A-Za-z0-9_-]{1,64}',k) for k in extras):
            raise ValueError('archive_dispatch_private_source_roots')
        targets.update({k:'/sources/'+k[7:] for k in extras})
        if set(policy['mounts'])!=set(targets):raise ValueError('archive_dispatch_complete_mount_set')
    mounts=[]
    writable={'keys','public_key','key_socket','public_result'} if key_service else {'private_result','public_result'}|({'encrypted'} if policy['action']=='export' else set())
    for name,target in targets.items():
        pin=policy['mounts'][name]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:raise ValueError('archive_dispatch_actual_volume_pin')
        path=PurePosixPath(pin['subpath'])
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or path.is_absolute() or not path.parts or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('archive_dispatch_canonical_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':name not in writable,
            'VolumeOptions':{'Subpath':pin['subpath']}})
    root=_directory(journal_directory,21001,21001,0o700)
    if any(root.iterdir()):raise RuntimeError('archive_original_dispatch_recovery_required')
    _save(root,'intent.json',{'kind':'ArchiveRoleDispatchIntent','policy_digest':policy['digest'],
        'automatic_reexecution_allowed':False})
    ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign'],stage='resource_archive_restore',
        operation_key='archive-'+policy['action']+'-'+policy['operation_ref'],
        seconds=policy['timeout_seconds']+policy['closure_seconds'],input_tokens=0,output_tokens=0,
        disk_bytes=policy['maximum_evidence_bytes'])
    env=['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
        'SKILLLOOP_ARCHIVE_POLICY_DIGEST='+policy['worker_policy_digest'],
        'SKILLLOOP_ARCHIVE_MAX_BYTES='+str(policy['maximum_evidence_bytes'])]
    if not key_service:env.append('SKILLLOOP_ARCHIVE_ACTION='+policy['action'])
    config={'Image':whole['image'],'User':str(uid)+':'+str(uid),'Entrypoint':['python'],
        'Cmd':['-m','skillloop.runtime.archive_key_service' if key_service else 'skillloop.runtime.encrypted_archive'],
        'Env':env,'Labels':{'skillloop.deployment_epoch':whole['deployment_epoch'],
            'skillloop.role':'archive_key_service' if key_service else 'encrypted_archive_'+policy['action'],
            'skillloop.action':policy['digest']},
        'HostConfig':{'GroupAdd':['21001','21005','21010'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'LogConfig':{'Type':'none','Config':{}},'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    identifier=engine.create('skillloop-archive-'+policy['action']+'-'+policy['digest'][7:31],config)
    actual=engine.inspect(identifier);_verify_role_process(actual,identifier,config,mounts)
    _save(root,'created.json',{'kind':'ArchiveRoleCreated','id':identifier,'inspection':actual,'configuration':config})
    engine.start(identifier)
    if key_service:
        started=time.monotonic()
        while time.monotonic()-started<policy['timeout_seconds']:
            actual=engine.inspect(identifier)
            if actual['State']['Running'] is not True:raise RuntimeError('archive_key_service_start_failed_preserve_key')
            try:result=read_owned(policy['result_path'],uid=21010,gid=21001,limit=262144)
            except FileNotFoundError:time.sleep(0.1);continue
            if (result.get('kind')!='OpaqueArchiveKeyServiceReady' or result.get('policy_digest')!=policy['worker_policy_digest']
                    or result.get('campaign')!=policy['campaign'] or result.get('deployment_epoch')!=whole['deployment_epoch']
                    or result.get('private_key_disclosed') is not False):raise ValueError('archive_actual_admin_key_ready')
            return _save(root,'completion.json',{'kind':'ArchiveKeyServiceDispatchCompletion',
                'worker_id':identifier,'configuration_digest':digest_jcs(config),'ready':result,
                'closure_seconds':policy['closure_seconds'],'resource_retired':False})
        raise TimeoutError('archive_original_key_service_readiness_unknown')
    wait=engine.wait(identifier,policy['timeout_seconds']);actual=engine.inspect(identifier)
    _verify_role_process(actual,identifier,config,mounts)
    if wait.get('StatusCode')!=0 or actual['State']['Running'] or actual['State']['ExitCode']!=0:
        raise RuntimeError('archive_original_role_failure_preserve_all_evidence')
    result=read_owned(policy['result_path'],uid=21005,gid=21001,limit=262144)
    kind='OpaqueEncryptedEvidenceExportCompletion' if policy['action']=='export' else 'OpaqueEncryptedEvidenceReviewCompletion'
    if (result.get('kind')!=kind or result.get('policy_digest')!=policy['worker_policy_digest']
            or result.get('deletion_authorized') is not False or result.get('campaign_coverage_complete') is not False):
        raise ValueError('archive_selected_inventory_only_actual_result')
    return _save(root,'completion.json',{'kind':'ArchiveRoleDispatchCompletion','worker_id':identifier,
        'configuration_digest':digest_jcs(config),'result':result,'resource_retired':False})


def close_archive_role(*,policy_path,dispatch_journal,review_path,journal_directory,engine):
    """Retire the original role process after independent encrypted review.

    Administrator keys, ciphertext, original evidence and all volumes remain.
    This is process closure, not campaign archive or authorization to delete.
    """
    from skillloop.runtime.protected_flow import _controller_record
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('archive_closure_actual_controller')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=2097152)
    dispatch=_controller_record(Path(dispatch_journal)/'completion.json')
    created=_controller_record(Path(dispatch_journal)/'created.json')
    intent=_controller_record(Path(dispatch_journal)/'intent.json')
    review=read_owned(review_path,uid=21005,gid=21001,limit=262144)
    expected_kind='ArchiveKeyServiceDispatchCompletion' if policy.get('action')=='key_service' else 'ArchiveRoleDispatchCompletion'
    if (intent.get('policy_digest')!=policy['digest'] or policy.get('kind')!='FrozenArchiveRoleDispatch'
            or dispatch.get('kind')!=expected_kind or dispatch.get('worker_id')!=created.get('id')
            or dispatch.get('configuration_digest')!=digest_jcs(created['configuration'])):
        raise ValueError('archive_closure_original_dispatch')
    if (review.get('kind')!='OpaqueEncryptedEvidenceReviewCompletion'
            or review.get('selected_inventory_verified') is not True or review.get('deletion_authorized') is not False):
        raise ValueError('archive_closure_independent_review_required')
    if policy['action']=='key_service':
        # Close only after a review from this key service's campaign scope. The
        # public ready record discloses no data key or private source identity.
        if (review.get('campaign')!=policy['campaign'] or review.get('deployment_epoch')!=policy['deployment_epoch']
                or review.get('key_id')!=dispatch['ready']['key_id']):
            raise ValueError('archive_key_closure_current_review_scope')
    else:
        original=dispatch['result']
        if (original.get('encrypted_bundle_digest')!=review.get('encrypted_bundle_digest')
                or original.get('policy_digest')!=review.get('policy_digest')):
            raise ValueError('archive_closure_exact_reviewed_bundle')
    root=_directory(journal_directory,21001,21001,0o700)
    if any(root.iterdir()):raise RuntimeError('archive_original_retirement_recovery_required')
    identifier=created['id'];actual=engine.inspect(identifier)
    original=created['inspection']
    _verify_role_process(actual,identifier,created['configuration'],created['configuration']['HostConfig']['Mounts'])
    if (actual['Id']!=identifier or actual.get('Config')!=original.get('Config')
            or actual.get('Image')!=original.get('Image') or actual.get('HostConfig')!=original.get('HostConfig')):
        raise ValueError('archive_closure_actual_original_role')
    _save(root,'intent.json',{'kind':'ArchiveRoleRetirementIntent','policy_digest':policy['digest'],
        'worker_id':identifier,'review_digest':review['digest'],'automatic_reexecution_allowed':False})
    if actual['State']['Running']:
        if policy['action']!='key_service':raise ValueError('archive_encryption_worker_not_stopped')
        engine.request('POST','/containers/'+identifier+'/stop?t=5',timeout=10)
        actual=engine.inspect(identifier)
    if actual['State']['Running'] or actual['State']['ExitCode']!=0:
        raise RuntimeError('archive_role_closure_unknown_or_failed_preserve_resources')
    engine.remove(identifier)
    return _save(root,'completion.json',{'kind':'ArchiveRoleRetirementCompletion','worker_id':identifier,
        'review_digest':review['digest'],'original_process_removed':True,'keys_preserved':True,
        'ciphertext_preserved':True,'source_evidence_preserved':True,'deletion_authorized':False})
