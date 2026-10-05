"""Controller dispatches the real roster Gate and consumes its freeze once."""
from datetime import datetime,timezone
import os
from pathlib import Path,PurePosixPath
import re
import stat

from skillloop.ci.campaign_registry import CampaignRegistry
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs,digest_bytes
from skillloop.proxy.qualification_authority import current_authority
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.docker_api import DockerEngine,DockerEngineError
from skillloop.runtime.protected_flow import _controller_record
from skillloop.runtime.evaluation_dispatch import _preserve_logs,_verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest


def dispatch_roster_gate(*,policy,assignment_directory,roster_directory,journal_directory,
                         authority_directory,whole_round_manifest_path,registry,ledger,engine,harden_only=False,executor=None):
    if type(harden_only) is not bool:raise ValueError('roster_dispatch_mode')
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or type(registry) is not CampaignRegistry or type(ledger) is not SpendingLedger):
        raise PermissionError('roster_dispatch_actual_controller')
    fields={'kind','campaign_digest','image','assignment_digest','whole_round_manifest_digest',
            'campaign_deadline','timeout_seconds','maximum_evidence_bytes','mounts',
            'deployment_manifest_path','deployment_journal','digest'}
    if (type(policy) is not dict or set(policy) not in (fields,fields|{'assignment_production_path'}) or policy['kind']!=
            ('FrozenDevelopmentHardenDispatch' if harden_only else 'FrozenDevelopmentRosterDispatch')
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=120
            or type(policy['maximum_evidence_bytes']) is not int
            or not 1<=policy['maximum_evidence_bytes']<=268435456):
        raise ValueError('roster_dispatch_original_frozen_policy')
    whole=read_round_manifest(whole_round_manifest_path)
    from skillloop.runtime.whole_deployment import WholeRoleDeployment
    _controller_record(Path(policy['deployment_journal'])/'provisioned.json')
    deployment=WholeRoleDeployment(manifest_path=policy['deployment_manifest_path'],
        journal_directory=policy['deployment_journal'],engine=engine,ledger=ledger,
        whole_round_manifest_path=whole_round_manifest_path)
    if deployment.plan['campaign_digest']!=policy['campaign_digest']:
        raise ValueError('roster_dispatch_original_deployment_campaign')
    keeper=deployment.provision()['keeper']
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21001 or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('roster_dispatch_private_journal')
    output=Path(roster_directory);info=output.lstat()
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21005 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750
            or any(output.iterdir()) or any(directory.iterdir())):
        raise PermissionError('roster_dispatch_fresh_output_or_recovery_required')
    if 'assignment_production_path' in policy:
        from skillloop.runtime.formal_phase import FormalPhaseExecutor
        from skillloop.runtime.roster_assignment import produce_roster_assignment
        if type(executor) is not FormalPhaseExecutor:
            raise PermissionError('roster_dispatch_original_phase_executor_required')
        job,assignment_binding=produce_roster_assignment(policy_path=policy['assignment_production_path'],
            expected_policy_digest=policy['assignment_digest'],campaign=policy['campaign_digest'],
            assignment_directory=assignment_directory,executor=executor,registry=registry,ledger=ledger,whole=whole)
    else:
        job=read_owned(Path(assignment_directory)/'job.json',uid=21001,gid=21005,limit=8388608)
        assignment_binding=job['digest']
    targets={'assignment':'/assignment','whole_round':'/whole-round','evaluation':'/evaluation',
        'task_reviews':'/task-reviews','applications':'/applications','scans':'/scans',
        'scan_reviews':'/scan-reviews','authority':'/authority-projection','roster':'/roster'}
    semantic_mounts=set(targets)|{'semantic','tokenizer'}
    if type(policy['mounts']) is dict and set(policy['mounts'])==semantic_mounts:
        targets.update(semantic='/semantic',tokenizer='/model')
    if type(policy['mounts']) is not dict or set(policy['mounts'])!=set(targets):
        raise ValueError('roster_dispatch_complete_readonly_evidence_mounts')
    mounts=[]
    for key,target in targets.items():
        pin=policy['mounts'][key]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:
            raise ValueError('roster_dispatch_mount_pin')
        path=PurePosixPath(pin['subpath'])
        if (type(pin['volume']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('roster_dispatch_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':key!='roster',
            'VolumeOptions':{'Subpath':pin['subpath']}})
    if policy['mounts']['roster']['volume']!=deployment.plan['volume']:
        raise ValueError('roster_dispatch_actual_keeper_output_volume')
    config={'Image':policy['image'],'User':'21005:21005','Entrypoint':['python'],
        'Cmd':['-m','skillloop.discovery.formal_harden_gate' if harden_only else 'skillloop.discovery.formal_roster_gate'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
               'SKILLLOOP_RAW_HISTORY_MAX_BYTES='+str(policy['maximum_evidence_bytes'])],
        'Labels':{'skillloop.role':'roster_gate','skillloop.whole_round':whole['digest'],
                  'skillloop.dispatch_policy':policy['digest']},
        'HostConfig':{'GroupAdd':['21001','21004'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    with registry.development_scope(campaign=policy['campaign_digest']) as state:
        deadline=datetime.fromisoformat(state['deadline'].replace('Z','+00:00'))
        spending=ledger.read()
        if (job.get('kind')!='FormalDevelopmentRosterAssignment' or assignment_binding!=policy['assignment_digest']
                or job.get('bindings')!=state['bindings'] or job.get('deadline')!=state['deadline']
                or policy['campaign_deadline']!=state['deadline']
                or job.get('whole_round_manifest_digest')!=whole['digest']
                or whole['digest']!=policy['whole_round_manifest_digest'] or policy['image']!=whole['image']
                or digest_jcs(job['config'])!=state['bindings']['config_digest']
                or ledger.campaign_started_at is None or deadline.timestamp()!=ledger.campaign_started_at+28800
                or spending.get('campaign_started_at')!=ledger.campaign_started_at
                or spending.get('executions')!=job.get('spent_entries')
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+120):
            raise ValueError('roster_dispatch_original_registry_and_complete_spending')
        cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='repair_pairing',
            operation_key='roster-'+policy['digest'][7:],seconds=policy['timeout_seconds']+60,
            input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
        _save(directory,'dispatch-intent.json',{'kind':'FormalDevelopmentRosterDispatchIntent',
            'configuration':config,'assignment_digest':job['digest'],'spending':cost,
            'policy_digest':policy['digest'],'started_at':datetime.now(timezone.utc).isoformat(),
            'deadline':deadline.isoformat(),'reserved_seconds':policy['timeout_seconds']+60,
            'roster_directory':str(output),'keeper':keeper})
        identifier=engine.create('skillloop-roster-'+policy['digest'][7:39],config)
        _save(directory,'created.json',{'kind':'FormalDevelopmentRosterCreated','container_id':identifier})
        try:
            _verify_role_process(engine.inspect(identifier),identifier,config,mounts)
            engine.start(identifier);wait=engine.wait(identifier,policy['timeout_seconds'])
            observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
            logs_digest=_preserve_logs(engine,identifier,directory,'process.log')
            _save(directory,'completion.json',{'kind':'FormalDevelopmentRosterProcessCompletion',
                'inspection':observed,'wait_result':wait,'logs_digest':logs_digest})
            if observed['State']['Running'] or wait['StatusCode'] or observed['State']['ExitCode']:
                raise RuntimeError('roster_gate_failed_no_private_epoch_release')
            evidence=read_owned(output/'development-evidence.json',uid=21005,gid=21001,limit=16777216)
            if harden_only:
                from skillloop.proxy.wire import validate_control
                result=read_owned(output/'harden-result.json',uid=21005,gid=21001,limit=262144)
                review=read_owned(output/'harden-review.json',uid=21005,gid=21001,limit=262144)
                validate_control(result)
                applications=evidence['applications']
                if (result['kind']!='HardenResult' or not applications
                        or review.get('kind')!='FormalDevelopmentHardenReview'
                        or review.get('assignment_digest')!=job['digest']
                        or review.get('development_evidence_digest')!=evidence['digest']
                        or review.get('result_digest')!=result['digest']
                        or review.get('roster_frozen') is not False or review.get('qualification_issued') is not False
                        or review.get('repair_round')!=applications[-1]['repair_round']
                        or result['body']['campaign_public_ref']!=policy['campaign_digest']
                        or result['body']['parent_subject_digest']!=applications[-1]['parent_subject_digest']
                        or result['body']['candidate_subject_digest']!=applications[-1]['candidate_bundle_digest']
                        or result['body']['patch_application_digest']!=applications[-1]['application_digest']
                        or os.path.lexists(output/'freeze.json')):
                    raise ValueError('harden_dispatch_actual_current_review_chain')
            else:
                freeze=read_owned(output/'freeze.json',uid=21005,gid=21001,limit=262144)
            if not harden_only and (freeze.get('kind')!='FrozenCampaignSubjectRoster'
                    or freeze.get('development_evidence_digest')!=evidence['digest']
                    or evidence.get('assignment_digest')!=job['digest']
                    or freeze.get('development_plan_digest')!=job['plan']['digest']
                    or freeze.get('subjects')!=evidence.get('subjects')):
                raise ValueError('roster_dispatch_actual_gate_freeze_chain')
            deployment.provision()  # Original Keeper must still preserve output.
        except BaseException as error:
            try:
                observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
                if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
                _save(directory,'failure.json',{'kind':'FormalDevelopmentRosterFailure','container_id':identifier,
                    'reason':str(error),'error_type':type(error).__name__,'automatic_replay_allowed':False})
            except BaseException as secondary:error.add_note('roster_custody_requires_recovery:'+type(secondary).__name__)
            raise
    if harden_only:
        _save(directory,'consumed.json',{'kind':'FormalDevelopmentHardenConsumed',
            'review_digest':review['digest'],'result_digest':result['digest'],
            'result':result,'container_id':identifier,'roster_frozen':False,'qualification_issued':False})
        return recover_roster_retirement(journal_directory=directory,engine=engine,policy_digest=policy['digest'])
    # The Gate review ran under the registry read transaction. Now serialize
    # consuming its result with live Proxy approval/plan-head publication too.
    with current_authority(authority_directory,epoch=state['bindings']['deployment_epoch'],
            config_digest=state['bindings']['config_digest'],trust_revision=state['bindings']['trust_revision'],
            approval_digests=job['approval_digests'],campaign=policy['campaign_digest']) as authority:
        heads=[h for h in authority.get('plan_heads',[]) if h['campaign_id']==policy['campaign_digest']]
        if len(heads)!=1 or heads[0]['plan_digest']!=job['plan']['digest']:
            raise ValueError('roster_dispatch_proxy_plan_changed_before_consumption')
        final=registry.freeze_subjects(campaign=policy['campaign_digest'],gate_freeze_path=output/'freeze.json')
    result={'freeze':freeze,'bindings':final,'inspection':observed,'container_id':identifier}
    _save(directory,'consumed.json',{'kind':'FormalDevelopmentRosterConsumed',
        'freeze_digest':freeze['digest'],'final_bindings':final,'result':result,
        'result_digest':digest_jcs(result),'container_id':identifier,'qualification_issued':False})
    return recover_roster_retirement(journal_directory=directory,engine=engine,policy_digest=policy['digest'])


def recover_roster_retirement(*,journal_directory,engine,policy_digest):
    """Retire only the original reviewed and consumed Gate; never run it again."""
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('roster_retirement_actual_controller')
    from skillloop.protection.current_task import _directory
    directory=_directory(journal_directory,21001,21001,0o700)
    intent=_controller_record(directory/'dispatch-intent.json')
    created=_controller_record(directory/'created.json')
    completed=_controller_record(directory/'completion.json')
    consumed=_controller_record(directory/'consumed.json')
    config=intent['configuration'];original=completed['inspection'];identifier=created['container_id']
    result=consumed['result'];harden=consumed.get('kind')=='FormalDevelopmentHardenConsumed'
    expected_digest=result.get('digest') if harden else digest_jcs(result)
    if (intent.get('kind')!='FormalDevelopmentRosterDispatchIntent'
            or intent.get('policy_digest')!=policy_digest
            or config.get('Labels',{}).get('skillloop.dispatch_policy')!=policy_digest
            or created.get('kind')!='FormalDevelopmentRosterCreated'
            or completed.get('kind')!='FormalDevelopmentRosterProcessCompletion'
            or consumed.get('kind') not in {'FormalDevelopmentHardenConsumed','FormalDevelopmentRosterConsumed'}
            or consumed['container_id']!=identifier or consumed['result_digest']!=expected_digest
            or original['State']['Running'] is not False or original['State']['ExitCode']!=0
            or completed['wait_result'].get('StatusCode')!=0):
        raise ValueError('roster_retirement_original_reviewed_process')
    _verify_role_process(original,identifier,config,config['HostConfig']['Mounts'])
    from skillloop.runtime.archive_files import open_original,require_unchanged,identity
    log_path=directory/'process.log'
    with os.fdopen(open_original(log_path),'rb') as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=21001
                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
                or before.st_size>1048576):
            raise PermissionError('roster_retirement_original_log_custody')
        raw=stream.read(1048577);after=os.fstat(stream.fileno())
    require_unchanged(log_path,before,after)
    if (identity(before)!=identity(after) or len(raw)!=before.st_size
            or digest_bytes(raw)!=completed['logs_digest']):
        raise ValueError('roster_retirement_original_logs_changed')
    output=Path(intent['roster_directory'])
    evidence=read_owned(output/'development-evidence.json',uid=21005,gid=21001,limit=16777216)
    if (evidence.get('kind')!='FormalDevelopmentRosterEvidence'
            or evidence.get('assignment_digest')!=intent['assignment_digest']):
        raise ValueError('roster_retirement_original_assignment_changed')
    if harden:
        from skillloop.proxy.wire import validate_control
        actual_result=read_owned(output/'harden-result.json',uid=21005,gid=21001,limit=262144)
        validate_control(actual_result)
        review=read_owned(output/'harden-review.json',uid=21005,gid=21001,limit=262144)
        if (actual_result!=result or actual_result.get('kind')!='HardenResult'
                or review.get('kind')!='FormalDevelopmentHardenReview'
                or review.get('assignment_digest')!=intent['assignment_digest']
                or review.get('roster_frozen') is not False or review.get('qualification_issued') is not False
                or review['digest']!=consumed['review_digest']
                or review['result_digest']!=expected_digest
                or review['development_evidence_digest']!=evidence['digest']
                or evidence['assignment_digest']!=intent['assignment_digest']
                or os.path.lexists(output/'freeze.json')):
            raise ValueError('roster_retirement_original_harden_output_changed')
    else:
        freeze=read_owned(output/'freeze.json',uid=21005,gid=21001,limit=262144)
        if (freeze!=result['freeze'] or freeze['digest']!=consumed['freeze_digest']
                or freeze.get('kind')!='FrozenCampaignSubjectRoster'
                or freeze.get('development_evidence_digest')!=evidence['digest']
                or freeze.get('subjects')!=evidence.get('subjects')
                or result['bindings']!=consumed['final_bindings']
                or result['inspection']!=original or result['container_id']!=identifier):
            raise ValueError('roster_retirement_original_freeze_changed')
    if (directory/'retired.json').exists():
        retired=_controller_record(directory/'retired.json')
        if (retired.get('kind')!='FormalDevelopmentGateRetired'
                or retired.get('result_digest')!=expected_digest
                or retired.get('container_id')!=identifier
                or retired.get('evidence_released') is not False
                or retired.get('budget_closure')!='within_original_budget'):
            raise ValueError('roster_retirement_original_completion')
        return result
    keeper=intent['keeper'];live=engine.inspect(keeper['Id'])
    if (any(live.get(k)!=keeper.get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
            or live['State']['Running'] is not True):
        raise RuntimeError('roster_retirement_original_keeper_unavailable')
    removing=directory/'removing.json'
    if removing.exists():
        record=_controller_record(removing)
        if record!={'kind':'FormalDevelopmentGateRemovalIntent','container_id':identifier,
                    'inspection':original,'result_digest':expected_digest,
                    'digest':digest_jcs({'kind':'FormalDevelopmentGateRemovalIntent','container_id':identifier,
                        'inspection':original,'result_digest':expected_digest})}:
            raise ValueError('roster_retirement_original_removal_intent')
    else:
        actual=engine.inspect(identifier)
        if any(actual.get(k)!=original.get(k) for k in ('Id','Image','Config','HostConfig','Mounts','State')):
            raise ValueError('roster_retirement_original_process_changed')
        _save(directory,'removing.json',{'kind':'FormalDevelopmentGateRemovalIntent',
            'container_id':identifier,'inspection':original,'result_digest':expected_digest})
    try:actual=engine.inspect(identifier)
    except DockerEngineError as error:
        if error.status!=404:raise
    else:
        if any(actual.get(k)!=original.get(k) for k in ('Id','Image','Config','HostConfig','Mounts','State')):
            raise ValueError('roster_retirement_actual_original_process')
        engine.request('DELETE','/containers/'+identifier+'?force=false&v=false')
        try:engine.inspect(identifier)
        except DockerEngineError as error:
            if error.status!=404:raise
        else:raise RuntimeError('roster_retirement_removal_not_observed')
    now=datetime.now(timezone.utc);began=datetime.fromisoformat(intent['started_at']);deadline=datetime.fromisoformat(intent['deadline'])
    if began.tzinfo is None or deadline.tzinfo is None or now<began:raise ValueError('roster_retirement_original_clock')
    elapsed=(now-began).total_seconds();within=now<deadline and elapsed<=intent['reserved_seconds']
    _save(directory,'retired.json',{'kind':'FormalDevelopmentGateRetired','container_id':identifier,
        'result_digest':expected_digest,'elapsed_seconds':elapsed,'evidence_released':False,
        'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure'})
    if not within:raise TimeoutError('roster_retirement_original_budget_expired')
    return result
