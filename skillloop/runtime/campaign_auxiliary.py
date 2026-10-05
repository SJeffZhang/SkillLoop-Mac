"""Original semantic/Gate worker custody, closure and deletion recovery."""
from datetime import datetime,timezone
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory
from skillloop.protocol import digest_jcs
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.protected_flow import _controller_record
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.docker_api import DockerEngine,DockerEngineError


def begin_auxiliary(step,deadline,uid,config):
    if os.geteuid()!=21001 or uid not in {21005,21011}:
        raise PermissionError('campaign_auxiliary_actual_controller')
    root=_directory(step['journal_directory'],21001,21001,0o700)
    if any(root.iterdir()) or os.path.lexists(step['result_path']):
        raise RuntimeError('campaign_auxiliary_original_operation_requires_recovery')
    now=datetime.now(timezone.utc)
    reserved=step['timeout_seconds']+step['closure_seconds']+60
    if deadline.tzinfo is None or (deadline-now).total_seconds()<=reserved:
        raise TimeoutError('campaign_auxiliary_original_budget')
    return _save(root,'intent.json',{'kind':'CampaignAuxiliaryIntent','step_digest':digest_jcs(step),
        'started_at':now.isoformat(),'deadline':deadline.isoformat(),'reserved_seconds':reserved,
        'uid':uid,'configuration':config,'result_path':step['result_path'],
        'result_limit':min(8388608,step['maximum_evidence_bytes'])})


def observe_auxiliary(step,inspection):
    root=_directory(step['journal_directory'],21001,21001,0o700)
    intent=_controller_record(root/'intent.json')
    config=intent['configuration']
    _verify_role_process(inspection,inspection['Id'],config,config['HostConfig']['Mounts'])
    return _save(root,'created.json',{'kind':'CampaignAuxiliaryCreated','inspection':inspection})


def finish_auxiliary(step,inspection,result,keeper,engine):
    root=_directory(step['journal_directory'],21001,21001,0o700)
    intent=_controller_record(root/'intent.json');created=_controller_record(root/'created.json')
    config=intent['configuration'];identifier=created['inspection']['Id']
    _verify_role_process(inspection,identifier,config,config['HostConfig']['Mounts'])
    if inspection['State']['Running'] is not False or inspection['State']['ExitCode']!=0:
        raise RuntimeError('campaign_auxiliary_original_worker_not_successful')
    if (keeper['State']['Running'] is not True or keeper.get('Image')!=config['Image']
            or keeper.get('Config',{}).get('User')!='21001:21001'
            or keeper.get('Config',{}).get('Labels',{}).get('skillloop.role')!='deployment_keeper'):
        raise RuntimeError('campaign_auxiliary_original_keeper_unavailable')
    original=read_owned(step['result_path'],uid=intent['uid'],gid=21001,limit=intent['result_limit'])
    if original!=result:raise ValueError('campaign_auxiliary_original_result_changed')
    _save(root,'reviewed.json',{'kind':'CampaignAuxiliaryReviewed','inspection':inspection,
        'result':result,'keeper':keeper,'step_digest':digest_jcs(step)})
    _save(root,'removing.json',{'kind':'CampaignAuxiliaryRemovalIntent','inspection':inspection})
    return recover_auxiliary_retirement(step,engine)


def preserve_auxiliary_failure(step,engine,error):
    root=_directory(step['journal_directory'],21001,21001,0o700)
    intent=_controller_record(root/'intent.json')
    if (root/'created.json').exists():
        created=_controller_record(root/'created.json');identifier=created['inspection']['Id']
        try:
            observed=engine.inspect(identifier);config=intent['configuration']
            _verify_role_process(observed,identifier,config,config['HostConfig']['Mounts'])
            if observed['State']['Running'] is True:
                engine.request('POST','/containers/'+identifier+'/stop?t='+str(step['closure_seconds']),
                               timeout=step['closure_seconds']+1)
            _save(root,'failed-process.json',{'kind':'CampaignAuxiliaryFailedProcess','inspection':engine.inspect(identifier)})
        except BaseException:pass
    if not (root/'failure.json').exists():
        _save(root,'failure.json',{'kind':'CampaignAuxiliaryFailure','error_type':type(error).__name__,
            'automatic_reexecution_allowed':False,'evidence_released':False})


def recover_auxiliary_retirement(step,engine):
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('campaign_auxiliary_retirement_actual_controller')
    root=_directory(step['journal_directory'],21001,21001,0o700)
    intent=_controller_record(root/'intent.json');created=_controller_record(root/'created.json')
    reviewed=_controller_record(root/'reviewed.json');removing=_controller_record(root/'removing.json')
    original=reviewed['inspection'];identifier=original['Id'];config=intent['configuration']
    if (intent.get('kind')!='CampaignAuxiliaryIntent' or created.get('kind')!='CampaignAuxiliaryCreated'
            or reviewed.get('kind')!='CampaignAuxiliaryReviewed' or removing.get('kind')!='CampaignAuxiliaryRemovalIntent'
            or intent['step_digest']!=digest_jcs(step) or reviewed['step_digest']!=digest_jcs(step)
            or created['inspection']['Id']!=identifier or removing['inspection']!=original
            or original['State']['Running'] is not False or original['State']['ExitCode']!=0):
        raise ValueError('campaign_auxiliary_original_retirement_binding')
    _verify_role_process(original,identifier,config,config['HostConfig']['Mounts'])
    result=read_owned(step['result_path'],uid=intent['uid'],gid=21001,limit=intent['result_limit'])
    if result!=reviewed['result']:raise ValueError('campaign_auxiliary_retirement_result_changed')
    completion=root/'completion.json'
    if completion.exists():
        value=_controller_record(completion)
        if (value.get('kind')!='CampaignAuxiliaryCompletion' or value['inspection']!=original
                or value['result_digest']!=result['digest'] or value['budget_closure']!='within_original_budget'):
            raise ValueError('campaign_auxiliary_original_completion')
        return result
    try:actual=engine.inspect(identifier)
    except DockerEngineError as error:
        if error.status!=404:raise
    else:
        if (any(actual.get(k)!=original.get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
                or actual['State']['Running'] is not False or actual['State']['ExitCode']!=0):
            raise ValueError('campaign_auxiliary_actual_original_process')
        engine.request('DELETE','/containers/'+identifier+'?force=false&v=false')
        try:engine.inspect(identifier)
        except DockerEngineError as error:
            if error.status!=404:raise
        else:raise RuntimeError('campaign_auxiliary_removal_not_observed')
    now=datetime.now(timezone.utc);started=datetime.fromisoformat(intent['started_at']);deadline=datetime.fromisoformat(intent['deadline'])
    if started.tzinfo is None or deadline.tzinfo is None or now<started:raise ValueError('campaign_auxiliary_original_clock')
    elapsed=(now-started).total_seconds();within=now<deadline and elapsed<=intent['reserved_seconds']
    _save(root,'completion.json',{'kind':'CampaignAuxiliaryCompletion','inspection':original,
        'result_digest':result['digest'],'elapsed_seconds':elapsed,'auxiliary_retired':True,'evidence_released':False,
        'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure'})
    if not within:raise TimeoutError('campaign_auxiliary_original_budget_expired')
    return result
