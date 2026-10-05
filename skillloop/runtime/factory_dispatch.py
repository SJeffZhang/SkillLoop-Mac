"""Controller starts the real private Factory under the frozen registry scope."""
from datetime import datetime,timezone
import os
from pathlib import Path,PurePosixPath
import re
import stat

from skillloop.ci.campaign_registry import CampaignRegistry
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.runtime.protected_flow import _controller_record


def dispatch_private_factory(*,policy,assignment_directory,projection_directory,gate_freeze_path,
                             journal_directory,whole_round_manifest_path,ledger,registry,engine):
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or type(registry) is not CampaignRegistry or type(ledger) is not SpendingLedger):
        raise PermissionError('private_factory_dispatch_actual_controller')
    fields={'kind','campaign_digest','image','whole_round_manifest_digest','assignment_digest',
            'campaign_deadline','timeout_seconds','maximum_evidence_bytes','keeper_id','mounts','digest'}
    if (type(policy) is not dict or set(policy)!=fields or policy['kind']!='FrozenPrivateFactoryDispatch'
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=120
            or type(policy['maximum_evidence_bytes']) is not int
            or not 1<=policy['maximum_evidence_bytes']<=33554432
            or not re.fullmatch(r'[0-9a-f]{64}',policy['keeper_id'])):
        raise ValueError('private_factory_frozen_dispatch')
    whole=read_round_manifest(whole_round_manifest_path)
    job=read_owned(Path(assignment_directory)/'job.json',uid=21001,gid=21004,limit=8388608)
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21001 or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('private_factory_private_dispatch_journal')
    if (directory/'dispatch-intent.json').exists():
        raise RuntimeError('private_factory_original_dispatch_requires_recovery')
    projection=Path(projection_directory);info=projection.lstat()
    if (not projection.is_absolute() or projection.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21004 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('private_factory_projection_grant')
    mounts=[]
    if type(policy['mounts']) is not dict or set(policy['mounts'])!={'assignment','whole_round','tokenizer','authority','private','projection','roster'}:
        raise ValueError('private_factory_mount_set')
    for key,target in (('assignment','/assignment'),('whole_round','/whole-round'),('tokenizer','/model'),
                       ('authority','/authority-projection'),('private','/private'),('projection','/factory-projection'),
                       ('roster','/roster')):
        pin=policy['mounts'][key]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:raise ValueError('private_factory_volume_pin')
        path=PurePosixPath(pin['subpath'])
        if (type(pin['volume']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('private_factory_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,
            'ReadOnly':key not in {'private','projection'},'VolumeOptions':{'Subpath':pin['subpath']}})
    config={'Image':policy['image'],'User':'21004:21004','Entrypoint':['python'],
        'Cmd':['-m','skillloop.protection.formal_factory'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
        'Labels':{'skillloop.role':'private_factory','skillloop.whole_round':whole['digest'],
                  'skillloop.dispatch_policy':policy['digest']},
        'HostConfig':{'GroupAdd':['21001'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'LogConfig':{'Type':'none','Config':{}},
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    def keeper():
        observed=engine.inspect(policy['keeper_id']);pin=policy['mounts']['private']
        whole_keeper=observed.get('Config',{}).get('Labels')=={
            'skillloop.deployment_epoch':whole['deployment_epoch'],'skillloop.role':'deployment_keeper'}
        selected=[m for m in observed.get('HostConfig',{}).get('Mounts',[])
            if m.get('Type')=='volume' and m.get('Source')==pin['volume']
            and m.get('ReadOnly') is True and (m.get('VolumeOptions',{}).get('Subpath')==pin['subpath']
                or whole_keeper and not m.get('VolumeOptions',{}).get('Subpath') and m.get('Target')=='/deployment-data')]
        host=observed.get('HostConfig',{});configuration=observed.get('Config',{});command=configuration.get('Cmd',[])
        if (observed.get('Id')!=policy['keeper_id'] or observed.get('Image')!=whole['image']
                or configuration.get('User')!='21001:21001' or configuration.get('Entrypoint')!=['python']
                or len(command)!=2 or command[0]!='-c' or not re.fullmatch(r'import time; ?time.sleep\([0-9]+\)',command[1])
                or observed.get('State',{}).get('Running') is not True
                or not whole_keeper and configuration.get('Labels',{}).get('skillloop.whole_round')!=whole['digest']
                or host.get('NetworkMode')!='none' or host.get('ReadonlyRootfs') is not True
                or host.get('CapDrop')!=['ALL'] or 'no-new-privileges' not in host.get('SecurityOpt',[])
                or host.get('LogConfig',{}).get('Type')!='none' or len(host.get('Mounts',[]))!=1 or len(selected)!=1):
            raise ValueError('private_factory_live_readonly_keeper_required')
        return observed
    with registry.private_scope(campaign=policy['campaign_digest']) as state:
        # Controller and Factory have separate mount namespaces. The job uses
        # only the fixed Factory path; the caller supplies the Controller alias.
        if job.get('gate_freeze_path')!='/roster/freeze.json':
            raise ValueError('private_factory_fixed_roster_path')
        freeze=read_owned(gate_freeze_path,uid=21005,gid=21001,limit=262144)
        deadline=datetime.fromisoformat(state['gate_freeze']['deadline'].replace('Z','+00:00'))
        if (freeze!=state['gate_freeze'] or job.get('gate_freeze_digest')!=freeze['digest']
                or job.get('digest')!=policy['assignment_digest']
                or job.get('campaign_id')!=policy['campaign_digest']
                or digest_jcs(job.get('config'))!=state['bindings']['config_digest']
                or job.get('trust_revision')!=state['bindings']['trust_revision']
                or job.get('whole_round_manifest_digest')!=whole['digest']
                or whole['digest']!=policy['whole_round_manifest_digest'] or policy['image']!=whole['image']
                or policy['campaign_deadline']!=state['gate_freeze']['deadline']
                or job.get('deadline')!=policy['campaign_deadline']
                or ledger.campaign_started_at is None or deadline.timestamp()!=ledger.campaign_started_at+28800
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+120):
            raise ValueError('private_factory_current_frozen_scope_binding')
        held=keeper()
        _save(directory,'dispatch-intent.json',{'kind':'FormalPrivateFactoryDispatchIntent',
            'configuration':config,'policy_digest':policy['digest'],'freeze_digest':freeze['digest'],'keeper_inspection':held,
            'started_at':datetime.now(timezone.utc).isoformat(),'reserved_seconds':policy['timeout_seconds']+60,
            'container_name':'skillloop-private-factory-'+policy['digest'][7:39]})
        cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='private_factory_lifecycle',
            operation_key='factory-'+policy['digest'][7:],seconds=policy['timeout_seconds']+60,
            input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
        _save(directory,'spending.json',{'kind':'FormalPrivateFactorySpending','spending':cost})
        identifier=None;name='skillloop-private-factory-'+policy['digest'][7:39]
        try:
            identifier=engine.create(name,config)
            _save(directory,'created.json',{'kind':'FormalPrivateFactoryCreated','container_id':identifier})
            initial=engine.inspect(identifier)
            _verify_role_process(initial,identifier,config,mounts)
            if initial.get('HostConfig',{}).get('LogConfig',{}).get('Type')!='none':
                raise ValueError('private_factory_logs_not_controller_visible')
            keeper()
            _save(directory,'starting.json',{'kind':'FormalPrivateFactoryStartIntent','container_id':identifier})
            engine.start(identifier);wait=engine.wait(identifier,policy['timeout_seconds'])
            observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
            held=keeper()
            if observed.get('HostConfig',{}).get('LogConfig',{}).get('Type')!='none':
                raise ValueError('private_factory_logs_not_controller_visible')
            _save(directory,'completion.json',{'kind':'FormalPrivateFactoryProcessCompletion',
                'inspection':observed,'wait_result':wait,
                'keeper_inspection':held,'private_evidence_released':False})
            if observed['State']['Running'] or wait['StatusCode'] or observed['State']['ExitCode']:
                raise RuntimeError('private_factory_failed_preserve_generation')
            result=read_owned(projection/(job['digest'][7:]+'.json'),uid=21004,gid=21001,limit=262144)
            if read_owned(projection/'commit.json',uid=21004,gid=21001,limit=262144)!=result:
                raise ValueError('private_factory_original_commit_locator')
            if (set(result)!={'kind','campaign_public_ref','opaque_ref','aggregate_status','digest'}
                    or result.get('kind')!='FormalPrivateFactoryCommit'
                    or result.get('campaign_public_ref')!=policy['campaign_digest']
                    or result.get('aggregate_status')!='sealed'
                    or type(result.get('opaque_ref')) is not str
                    or not re.fullmatch(r'protected-[0-9a-f]{32}',result['opaque_ref'])):
                raise ValueError('private_factory_actual_commit_projection')
            original_intent=_controller_record(directory/'dispatch-intent.json')
            within=(datetime.now(timezone.utc)-datetime.fromisoformat(original_intent['started_at'])).total_seconds()<=policy['timeout_seconds']+60 and datetime.now(timezone.utc)<deadline
            _save(directory,'commit-review.json',{'kind':'FormalPrivateFactoryCommitReview','commit':result,
                'policy_digest':policy['digest'],'inspection':observed,'keeper_inspection':held,
                'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure'})
            if not within:raise TimeoutError('private_factory_original_budget_expired')
            return {'commit':result,'container_id':identifier,'inspection':observed,
                'private_evidence_released':False,'host_backend_lifecycle_verified':False}
        except BaseException as error:
            try:
                if identifier is None:
                    # A lost create response is never permission to POST a
                    # replacement. Inspect only the original unique name.
                    actual=engine.inspect(name)
                    _verify_role_process(actual,actual['Id'],config,mounts)
                    intent=_controller_record(directory/'dispatch-intent.json')
                    created=datetime.fromisoformat(actual['Created'].replace('Z','+00:00'))
                    if created<datetime.fromisoformat(intent['started_at']):raise ValueError('private_factory_unknown_create_identity')
                    identifier=actual['Id']
                    _save(directory,'create-observation.json',{'kind':'FormalPrivateFactoryUnknownCreateObservation',
                        'inspection':actual,'automatic_regeneration_allowed':False})
                observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
                if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
                observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
                _save(directory,'failure.json',{'kind':'FormalPrivateFactoryFailure','container_id':identifier,
                    'error_type':type(error).__name__,'inspection':observed,'automatic_regeneration_allowed':False,
                    'private_evidence_released':False})
            except BaseException as secondary:error.add_note('private_factory_custody_requires_recovery:'+type(secondary).__name__)
            raise


def recover_private_factory(*,policy,journal_directory,projection_directory,registry,engine,ledger):
    """Recover only the original reviewed commit, never repeat epoch creation."""
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('private_factory_recovery_actual_controller')
    root=Path(journal_directory)
    intent=_controller_record(root/'dispatch-intent.json')
    reviewed=_controller_record(root/'commit-review.json')
    completion=_controller_record(root/'completion.json')
    created=_controller_record(root/'created.json')
    spending=_controller_record(root/'spending.json')['spending']
    original=reviewed['inspection'];identifier=original['Id']
    if (intent.get('kind')!='FormalPrivateFactoryDispatchIntent' or intent['policy_digest']!=policy['digest']
            or reviewed.get('kind')!='FormalPrivateFactoryCommitReview' or reviewed['policy_digest']!=policy['digest']
            or reviewed.get('budget_closure')!='within_original_budget'
            or completion.get('kind')!='FormalPrivateFactoryProcessCompletion'
            or completion['inspection']!=original or completion['wait_result'].get('StatusCode')!=0
            or created.get('kind')!='FormalPrivateFactoryCreated' or created['container_id']!=identifier
            or original['State']['Running'] is not False or original['State']['ExitCode']!=0
            or spending['operation_key']!='factory-'+policy['digest'][7:]
            or spending['requested_cost']!={'seconds':policy['timeout_seconds']+60,'input_tokens':0,
                'output_tokens':0,'disk_bytes':policy['maximum_evidence_bytes']}
            or spending not in ledger.read().get('auxiliary_executions',[])):
        raise ValueError('private_factory_original_reviewed_commit_required')
    with registry.private_scope(campaign=policy['campaign_digest']) as state:
        if intent['freeze_digest']!=state['gate_freeze']['digest']:
            raise ValueError('private_factory_recovery_original_frozen_roster')
        config=intent['configuration'];mounts=config['HostConfig']['Mounts']
        actual=engine.inspect(identifier);_verify_role_process(actual,identifier,config,mounts)
        if (any(actual.get(k)!=original.get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
                or actual['State']['Running'] is not False or actual['State']['ExitCode']!=0):
            raise ValueError('private_factory_recovery_original_process')
        held=engine.inspect(policy['keeper_id']);prior=reviewed['keeper_inspection']
        if (any(held.get(k)!=prior.get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
                or held['State']['Running'] is not True):
            raise ValueError('private_factory_recovery_keeper_custody')
        result=read_owned(Path(projection_directory)/(policy['assignment_digest'][7:]+'.json'),
            uid=21004,gid=21001,limit=262144)
        if result!=reviewed['commit']:raise ValueError('private_factory_recovery_original_commit_bytes')
        if read_owned(Path(projection_directory)/'commit.json',uid=21004,gid=21001,limit=262144)!=result:
            raise ValueError('private_factory_recovery_commit_locator')
        return {'commit':result,'container_id':identifier,'inspection':actual,
            'private_evidence_released':False,'host_backend_lifecycle_verified':False}
