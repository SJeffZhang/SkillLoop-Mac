"""Controller calls the independent lifecycle Gate, reading only its projection."""
from datetime import datetime,timezone
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory
from skillloop.protocol import digest_jcs
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.whole_deployment import WholeRoleDeployment


def dispatch_lifecycle_review(*,policy_path,manifest_path,deployment_journal,journal_directory,
                              result_path,whole_round_manifest_path,ledger,engine):
    if os.geteuid()!=21001:raise PermissionError('lifecycle_dispatch_actual_controller')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=262144)
    fields={'kind','campaign','deployment_epoch','whole_round_manifest_digest','deployment_digest',
            'deadline','timeout_seconds','closure_seconds','maximum_evidence_bytes','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenNativeLifecycleGateDispatch'
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=120
            or type(policy['closure_seconds']) is not int or not 30<=policy['closure_seconds']<=120
            or type(policy['maximum_evidence_bytes']) is not int or not 1048576<=policy['maximum_evidence_bytes']<=8388608):
        raise ValueError('lifecycle_dispatch_original_full_cost')
    deployment=WholeRoleDeployment(manifest_path=manifest_path,journal_directory=deployment_journal,
        engine=engine,ledger=ledger,whole_round_manifest_path=whole_round_manifest_path)
    plan=deployment.plan;whole=deployment.whole
    deadline=datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'))
    if (policy['deployment_digest']!=plan['digest'] or policy['whole_round_manifest_digest']!=whole['digest']
            or policy['deployment_epoch']!=whole['deployment_epoch'] or policy['campaign']!=plan['campaign_digest']
            or deadline.tzinfo is None or ledger.campaign_started_at is None
            or deadline.timestamp()!=ledger.campaign_started_at+28800
            or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+policy['closure_seconds']+60):
        raise ValueError('lifecycle_dispatch_source_epoch_original_clock')
    config=deployment.role_config('gate','skillloop.protection.model_lifecycle_gate')
    if config['Cmd']!=['-m','skillloop.protection.model_lifecycle_gate']:
        raise ValueError('lifecycle_dispatch_independent_gate_entry')
    if not {'21001','21004','21011'}<=set(config['HostConfig']['GroupAdd']):
        raise PermissionError('lifecycle_dispatch_exact_gate_write_groups')
    required={'/lifecycle':True,'/private-authority':True,'/reviews':False,
              '/gateway-review':False,'/public-lifecycle':False}
    mounts={m['Target']:m for m in config['HostConfig']['Mounts']}
    for target,readonly in required.items():
        pin=mounts.get(target)
        if pin is None or pin['ReadOnly'] is not readonly:
            raise PermissionError('lifecycle_dispatch_exact_custody_mounts')
    projection=_directory(Path(result_path).parent,21005,21001,0o750)
    if Path(result_path).name!='completion.json' or any(projection.iterdir()):
        raise RuntimeError('lifecycle_dispatch_original_projection_requires_recovery')
    journal=_directory(journal_directory,21001,21001,0o700)
    if any(journal.iterdir()):raise RuntimeError('lifecycle_dispatch_started_gate_no_reexecution')
    _save(journal,'intent.json',{'kind':'ControllerNativeLifecycleGateIntent','policy_digest':policy['digest'],
        'deployment_digest':plan['digest'],'started_at':datetime.now(timezone.utc).isoformat(),
        'deadline':policy['deadline'],'reserved_seconds':policy['timeout_seconds']+policy['closure_seconds']+60,
        'automatic_reexecution_allowed':False})
    spending=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign'],stage='private_factory_lifecycle',
        operation_key='lifecycle-gate-'+policy['digest'][7:],
        seconds=policy['timeout_seconds']+policy['closure_seconds'],input_tokens=0,output_tokens=0,
        disk_bytes=policy['maximum_evidence_bytes'])
    _save(journal,'spending.json',{'kind':'ControllerNativeLifecycleGateSpending','spending':spending})
    observed=deployment.start_role('gate','lifecycle-'+policy['digest'][7:],module='skillloop.protection.model_lifecycle_gate')
    identifier=observed['inspection']['Id']
    _save(journal,'process.json',{'kind':'ControllerNativeLifecycleGateProcess','inspection':observed['inspection']})
    try:
        wait=engine.wait(identifier,policy['timeout_seconds']);actual=engine.inspect(identifier)
        from skillloop.runtime.evaluation_dispatch import _verify_role_process
        _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
        if wait.get('StatusCode')!=0 or actual['State']['Running'] is not False or actual['State']['ExitCode']!=0:
            raise RuntimeError('lifecycle_independent_gate_unavailable_preserve_original')
        result=read_owned(result_path,uid=21005,gid=21001,limit=262144)
        if (set(result)!={'kind','campaign_public_ref','deployment_epoch','aggregate_status','qualification_issued','digest'}
                or result['kind']!='OpaqueNativeLifecycleReviewCompletion' or result['aggregate_status']!='reviewed'
                or result['campaign_public_ref']!=policy['campaign'] or result['deployment_epoch']!=policy['deployment_epoch']
                or result['qualification_issued'] is not False):
            raise ValueError('lifecycle_original_gate_projection')
        # Gate's three outputs are durable in the shared persistent volume.
        # Keep that volume and its original readonly Keeper; removing only the
        # stopped worker cannot implicitly remove any evidence mount.
        held=engine.inspect(deployment.provision()['keeper']['Id'])
        if held['State']['Running'] is not True:raise RuntimeError('lifecycle_gate_keeper_required_until_export')
        _save(journal,'reviewed.json',{'kind':'ControllerNativeLifecycleGateReviewed',
            'projection':result,'inspection':actual,'keeper_inspection':held,
            'evidence_released':False,'qualification_issued':False})
        _save(journal,'removing.json',{'kind':'ControllerNativeLifecycleGateRemovalIntent',
            'container_id':identifier,'inspection':actual,'evidence_volume_retained':True})
        return recover_lifecycle_retirement(journal_directory=journal_directory,policy_digest=policy['digest'],engine=engine)
    except BaseException as error:
        # Preserve the actual process and all role-owned bytes. Controller has
        # no mount/read grant for Gate's private diagnostics or original raw.
        try:
            actual=engine.inspect(identifier)
            from skillloop.runtime.evaluation_dispatch import _verify_role_process
            _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
            if actual['State']['Running']:
                engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            _save(journal,'failed-process.json',{'kind':'ControllerNativeLifecycleGateStoppedFailure',
                'inspection':engine.inspect(identifier),'evidence_released':False})
        except BaseException as secondary:error.add_note('lifecycle_gate_original_custody:'+type(secondary).__name__)
        _save(journal,'failure.json',{'kind':'ControllerNativeLifecycleGateFailure',
            'error_type':type(error).__name__,'container_id':identifier,'automatic_reexecution_allowed':False,
            'evidence_released':False,'qualification_issued':False})
        raise


def recover_lifecycle_retirement(*,journal_directory,policy_digest,engine):
    """Reconcile only deletion after the original independent review."""
    from skillloop.runtime.protected_flow import _controller_record
    from skillloop.runtime.docker_api import DockerEngine,DockerEngineError
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('lifecycle_retirement_actual_controller')
    journal=_directory(journal_directory,21001,21001,0o700)
    intent=_controller_record(journal/'intent.json')
    reviewed=_controller_record(journal/'reviewed.json')
    removing=_controller_record(journal/'removing.json')
    actual_original=reviewed['inspection'];identifier=actual_original['Id']
    if (intent.get('kind')!='ControllerNativeLifecycleGateIntent' or intent['policy_digest']!=policy_digest
            or reviewed.get('kind')!='ControllerNativeLifecycleGateReviewed'
            or removing.get('kind')!='ControllerNativeLifecycleGateRemovalIntent'
            or removing['container_id']!=identifier or removing['inspection']!=actual_original
            or actual_original['State']['Running'] is not False or actual_original['State']['ExitCode']!=0
            or reviewed['projection'].get('aggregate_status')!='reviewed'):
        raise ValueError('lifecycle_retirement_original_reviewed_process')
    completed=journal/'completion.json'
    if completed.exists():
        result=_controller_record(completed)
        if result.get('kind')!='ControllerNativeLifecycleGateCompletion' or result['projection']!=reviewed['projection'] or result['inspection']!=actual_original:
            raise ValueError('lifecycle_retirement_original_completion')
        if result['budget_closure']!='within_original_budget':raise TimeoutError('lifecycle_retirement_original_budget_expired')
        return result
    try:actual=engine.inspect(identifier)
    except DockerEngineError as error:
        if error.status!=404:raise
    else:
        if (any(actual.get(k)!=actual_original.get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
                or actual['State']['Running'] is not False or actual['State']['ExitCode']!=0):
            raise ValueError('lifecycle_retirement_actual_original_stopped_process')
        engine.request('DELETE','/containers/'+identifier+'?force=false&v=false')
        try:engine.inspect(identifier)
        except DockerEngineError as error:
            if error.status!=404:raise
        else:raise RuntimeError('lifecycle_gate_removal_not_observed')
    now=datetime.now(timezone.utc);started=datetime.fromisoformat(intent['started_at']);deadline=datetime.fromisoformat(intent['deadline'].replace('Z','+00:00'))
    if started.tzinfo is None or deadline.tzinfo is None or now<started:raise ValueError('lifecycle_retirement_original_utc')
    elapsed=(now-started).total_seconds();within=now<deadline and elapsed<=intent['reserved_seconds']
    result=_save(journal,'completion.json',{'kind':'ControllerNativeLifecycleGateCompletion',
        'projection':reviewed['projection'],'inspection':actual_original,'evidence_released':False,
        'auxiliary_retired':True,'qualification_issued':False,'elapsed_seconds':elapsed,
        'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure'})
    if not within:raise TimeoutError('lifecycle_retirement_original_budget_expired')
    return result
