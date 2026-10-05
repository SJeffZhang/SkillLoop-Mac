"""Bounded actual Admin/Reporter execution and original-process retirement."""
from datetime import datetime,timezone
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import digest_jcs
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.protected_flow import _controller_record
from skillloop.runtime.whole_deployment import WholeRoleDeployment
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.docker_api import DockerEngine,DockerEngineError


def dispatch_role_command(*,step,operation_id,whole_round_manifest_path,ledger,engine):
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('role_dispatch_actual_controller')
    uid=21010 if step['role']=='admin' else 21009
    deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['deployment_journal'],
        engine=engine,ledger=ledger,whole_round_manifest_path=whole_round_manifest_path)
    deadline=deployment.deadline;reserved=step['timeout_seconds']+step['closure_seconds']
    if (deadline-datetime.now(timezone.utc)).total_seconds()<=reserved+60:
        raise TimeoutError('role_dispatch_original_terminal_budget')
    journal=_directory(step['journal_directory'],21001,21001,0o700)
    assignment=_directory(step['assignment_directory'],21001,uid,0o750)
    if any(journal.iterdir()) or any(assignment.iterdir()) or os.path.lexists(step['result_path']):
        raise RuntimeError('role_dispatch_original_operation_requires_recovery')
    job={'kind':'DelegatedRoleCommand','command':step['role_command'],'operation_id':operation_id,'params':step['rpc_params']}
    job['digest']=digest_jcs(job)
    _save(journal,'intent.json',{'kind':'ControllerRoleCommandIntent','step_digest':digest_jcs(step),
        'job_digest':job['digest'],'role_uid':uid,'result_path':step['result_path'],
        'started_at':datetime.now(timezone.utc).isoformat(),'deadline':deadline.isoformat(),
        'reserved_seconds':reserved+60,'maximum_evidence_bytes':step['maximum_evidence_bytes']})
    stage='private_factory_lifecycle' if step['role_command']=='import-lifecycle' else ('gate_qualification_report' if uid==21009 else (
        'repair_pairing' if step['role_command'] in {'produce-candidate','produce-plan'} else 'approval_deployment'))
    ledger.consume_auxiliary(manifest=deployment.whole,campaign=deployment.plan['campaign_digest'],stage=stage,
        operation_key='role-command-'+job['digest'][7:],seconds=reserved,input_tokens=0,output_tokens=0,
        disk_bytes=step['maximum_evidence_bytes'])
    _publish(assignment/'job.json',job,uid)
    config=deployment.plan['roles'][step['role']]['config'];identifier=None
    try:
        observed=deployment.start_role(step['role'],operation_id+'-'+step['role'])
        identifier=observed['inspection']['Id']
        _save(journal,'created.json',{'kind':'ControllerRoleCommandCreated','id':identifier,'inspection':observed['inspection']})
        waited=engine.wait(identifier,min(step['timeout_seconds'],max(1,(deadline-datetime.now(timezone.utc)).total_seconds())))
        actual=engine.inspect(identifier)
        _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
        if (waited.get('StatusCode')!=0 or actual['State']['Running'] is not False or actual['State']['ExitCode']!=0):
            raise RuntimeError('role_dispatch_original_worker_failed')
        result=read_owned(step['result_path'],uid=uid,gid=21001,limit=min(2097152,step['maximum_evidence_bytes']))
        provisioned=_controller_record(Path(step['deployment_journal'])/'provisioned.json')
        keeper=engine.inspect(provisioned['keeper']['Id'])
        if keeper['State']['Running'] is not True:
            raise RuntimeError('role_dispatch_keeper_not_alive_preserve_evidence')
        _save(journal,'reviewed.json',{'kind':'ControllerRoleCommandReviewed','inspection':actual,'result':result,
            'step_digest':digest_jcs(step),'keeper_inspection':keeper,'evidence_released':False})
        _save(journal,'removing.json',{'kind':'ControllerRoleCommandRemovalIntent','inspection':actual,'id':identifier})
        return recover_role_command_retirement(step=step,engine=engine)
    except BaseException as error:
        # Stop only the exact observed worker. Never delete failed output or
        # treat an unknown create as a reason to launch another role process.
        if identifier is not None:
            try:
                actual=engine.inspect(identifier)
                _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
                if actual['State']['Running'] is True:
                    engine.request('POST','/containers/'+identifier+'/stop?t='+str(step['closure_seconds']),timeout=step['closure_seconds']+1)
                _save(journal,'failed-process.json',{'kind':'ControllerRoleCommandFailedProcess','inspection':engine.inspect(identifier)})
            except BaseException:pass
        if not (journal/'failure.json').exists():
            _save(journal,'failure.json',{'kind':'ControllerRoleCommandFailure','error_type':type(error).__name__,
                'evidence_released':False,'automatic_reexecution_allowed':False})
        raise


def recover_role_command_retirement(*,step,engine):
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('role_retirement_actual_controller')
    journal=_directory(step['journal_directory'],21001,21001,0o700)
    intent=_controller_record(journal/'intent.json');reviewed=_controller_record(journal/'reviewed.json')
    removing=_controller_record(journal/'removing.json')
    original=reviewed['inspection'];identifier=original['Id']
    if (intent.get('kind')!='ControllerRoleCommandIntent' or reviewed.get('kind')!='ControllerRoleCommandReviewed'
            or removing.get('kind')!='ControllerRoleCommandRemovalIntent'
            or intent['step_digest']!=digest_jcs(step) or reviewed['step_digest']!=digest_jcs(step)
            or removing['inspection']!=original or removing['id']!=identifier
            or original['State']['Running'] is not False or original['State']['ExitCode']!=0
            or original['Config']['User']!=str(intent['role_uid'])+':'+str(intent['role_uid'])):
        raise ValueError('role_retirement_original_successful_process')
    result=read_owned(step['result_path'],uid=intent['role_uid'],gid=21001,limit=min(2097152,intent['maximum_evidence_bytes']))
    if result!=reviewed['result']:raise ValueError('role_retirement_original_result_changed')
    completed=journal/'completion.json'
    if completed.exists():
        value=_controller_record(completed)
        if (value.get('kind')!='ControllerRoleCommandCompletion' or value['inspection']!=original
                or value['result_digest']!=result['digest'] or value['budget_closure']!='within_original_budget'):
            raise ValueError('role_retirement_original_completion')
        return result
    try:actual=engine.inspect(identifier)
    except DockerEngineError as error:
        if error.status!=404:raise
    else:
        if (any(actual.get(k)!=original.get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
                or actual['State']['Running'] is not False or actual['State']['ExitCode']!=0):
            raise ValueError('role_retirement_actual_original_identity')
        engine.request('DELETE','/containers/'+identifier+'?force=false&v=false')
        try:engine.inspect(identifier)
        except DockerEngineError as error:
            if error.status!=404:raise
        else:raise RuntimeError('role_retirement_removal_not_observed')
    now=datetime.now(timezone.utc);started=datetime.fromisoformat(intent['started_at']);deadline=datetime.fromisoformat(intent['deadline'])
    if started.tzinfo is None or deadline.tzinfo is None or now<started:
        raise ValueError('role_retirement_original_clock')
    elapsed=(now-started).total_seconds();within=now<deadline and elapsed<=intent['reserved_seconds']
    _save(journal,'completion.json',{'kind':'ControllerRoleCommandCompletion','inspection':original,
        'result_digest':result['digest'],'elapsed_seconds':elapsed,'auxiliary_retired':True,'evidence_released':False,
        'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure'})
    if not within:raise TimeoutError('role_retirement_original_budget_expired')
    return result
