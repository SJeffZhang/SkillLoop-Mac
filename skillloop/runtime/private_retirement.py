"""Private Gate authorizes exact resource retirement without disclosing results."""
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory,_publish


def authorize_retirement(*,authority,session_key,mapping_path,completion_path,
                         task_review_path,archive_review_path,output_directory):
    if os.geteuid()!=21005 or not authority.readonly:
        raise PermissionError('private_retirement_independent_gate_snapshot')
    pins=authority.formal_session_identity(session_key)
    with authority.connect() as db:
        session=db.execute('SELECT state,result_digest FROM sessions WHERE key=?',(session_key,)).fetchone()
    if session is None or session[0]!='complete':
        raise ValueError('private_retirement_session_not_complete')
    mapping=read_owned(mapping_path,uid=21004,gid=21004,limit=262144)
    completion=read_owned(completion_path,uid=21001,gid=21004,limit=2097152)
    task=read_owned(task_review_path,uid=21005,gid=21004,limit=262144)
    archive=read_owned(archive_review_path,uid=21005,gid=21004,limit=262144)
    reference=mapping['launch']
    with authority.connect() as db:
        claim=db.execute('SELECT launch_action,opaque_ref,launch_digest FROM formal_runtime_materializations WHERE session_key=?',(session_key,)).fetchone()
    if claim!=(mapping.get('action_digest'),reference.get('opaque_ref'),reference.get('digest')):
        raise ValueError('private_retirement_committed_original_launch')
    opaque=completion['business_closure'];closure=opaque['closure']
    for value in (reference,opaque,closure):
        if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
            raise ValueError('private_retirement_original_closure_seal')
    if (mapping.get('kind')!='PrivateRunLaunchMapping' or mapping.get('session_key')!=session_key
            or completion.get('kind')!='OpaquePrivateRuntimeCompletion'
            or completion.get('reference_digest')!=reference['digest']
            or opaque.get('reference_digest')!=reference['digest']
            or closure.get('evidence_released') is not False
            or task.get('kind')!='FormalTaskEvidenceReview' or task.get('evidence_complete') is not True
            or task.get('intent_digest')!=pins['intent_digest'] or task.get('entry_digest')!=pins['entry_digest']
            or task.get('execution_record_digest')!=session[1]
            or archive.get('kind')!='FormalTaskArchiveReview' or archive.get('complete') is not True
            or archive.get('task_review_digest')!=task['digest']
            or archive.get('intent_digest')!=pins['intent_digest']
            or archive.get('entry_digest')!=pins['entry_digest']
            or completion.get('evidence_released') is not False):
        raise ValueError('private_retirement_complete_original_chain_required')
    # No private plan, case, execution result or raw archive digest crosses here.
    grant={'kind':'OpaquePrivateRetirementGrant','reference_digest':reference['digest'],
        'completion_digest':completion['digest'],'opaque_closure_digest':opaque['digest'],
        'worker_id':closure['stopped_container_id'],'keeper_id':closure['keeper_id'],
        'run_volume':closure['run_volume'],'archive_verified':True,'session_complete':True,
        'gate_uid':21005,'qualification_issued':False}
    grant['digest']=digest_jcs(grant)
    output=_directory(output_directory,21005,21001,0o750)
    _publish(output/(reference['opaque_ref']+'.json'),grant,21001)
    return grant


def retire_private_runtime(*,reference,completion,grant_path,journal_directory,engine):
    """Release only the original Runtime volume after a private Gate grant."""
    from skillloop.runtime.docker_api import DockerEngine
    from skillloop.runtime.proposal_dispatch import _save
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('private_retirement_actual_controller')
    grant=read_owned(grant_path,uid=21005,gid=21001,limit=262144)
    for value in (reference,completion):
        if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
            raise ValueError('private_retirement_changed_original_controller_record')
    opaque=completion['business_closure'];closure=opaque['closure']
    if (grant.get('kind')!='OpaquePrivateRetirementGrant' or grant.get('gate_uid')!=21005
            or grant.get('archive_verified') is not True or grant.get('session_complete') is not True
            or grant.get('qualification_issued') is not False
            or grant.get('reference_digest')!=reference['digest']
            or completion.get('reference_digest')!=reference['digest']
            or grant.get('completion_digest')!=completion['digest']
            or grant.get('opaque_closure_digest')!=opaque['digest']
            or any(grant.get(k)!=closure.get(v) for k,v in
                (('worker_id','stopped_container_id'),('keeper_id','keeper_id'),('run_volume','run_volume')))):
        raise ValueError('private_retirement_exact_gate_authorization')
    root=_directory(journal_directory,21001,21001,0o700)
    from skillloop.runtime.protected_flow import _controller_record
    from skillloop.runtime.docker_api import DockerEngineError
    intent_path=root/'retirement-intent.json'
    if intent_path.exists():
        intent=_controller_record(intent_path)
        if (intent.get('kind')!='OpaquePrivateRetirementIntent' or intent.get('grant_digest')!=grant['digest']
                or intent.get('automatic_reexecution_allowed') is not False
                or intent.get('worker',{}).get('Id')!=grant['worker_id']
                or intent.get('keeper',{}).get('Id')!=grant['keeper_id']
                or intent.get('volume',{}).get('Name')!=grant['run_volume']):
            raise ValueError('private_retirement_changed_original_intent')
        worker,keeper,volume=(intent[k] for k in ('worker','keeper','volume'))
    else:
        if any(root.iterdir()):raise ValueError('private_retirement_unrecognized_journal')
        worker=engine.inspect(grant['worker_id']);keeper=engine.inspect(grant['keeper_id'])
        volume=engine.inspect_volume(grant['run_volume'])
        original=completion['inspection'];request=original['Config']['Labels']['skillloop.run_request']
        if (worker.get('Id')!=original['Id'] or worker.get('Image')!=original['Image']
                or worker.get('Config')!=original['Config'] or worker.get('State',{}).get('Running') is not False
                or worker.get('State',{}).get('ExitCode')!=closure['actual_exit_code']
                or keeper.get('Id')!=grant['keeper_id'] or keeper.get('Image')!=worker['Image']
                or keeper.get('Config',{}).get('User')!='21001:21001'
                or keeper.get('State',{}).get('Running') is not True
                or digest_jcs(keeper)!=closure['keeper_inspection_digest']
                or volume.get('Name')!=grant['run_volume']
                or volume.get('Labels',{}).get('skillloop.run_request')!=request
                or not any(m.get('Name')==volume['Name'] and m.get('RW') is False for m in keeper.get('Mounts',[]))):
            raise ValueError('private_retirement_actual_original_resources')
        intent=_save(root,intent_path.name,{'kind':'OpaquePrivateRetirementIntent',
            'grant_digest':grant['digest'],'worker':worker,'keeper':keeper,'volume':volume,
            'automatic_reexecution_allowed':False})
    completed=root/'retirement-completion.json'
    if completed.exists():
        result=_controller_record(completed)
        if (result.get('kind')!='OpaquePrivateRetirementCompletion'
                or result.get('grant_digest')!=grant['digest'] or result.get('reference_digest')!=reference['digest']
                or result.get('original_runtime_resources_released') is not True):
            raise ValueError('private_retirement_changed_completion')
        return result
    for name,original in (('worker',worker),('keeper',keeper)):
        done=root/(name+'-removed.json');started=root/(name+'-removing.json')
        if done.exists():
            receipt=_controller_record(done)
            if receipt.get('container_id')!=original['Id'] or receipt.get('intent_digest')!=intent['digest']:
                raise ValueError('private_retirement_changed_removal_receipt')
            continue
        removing=_controller_record(started) if started.exists() else None
        if removing is not None and (removing.get('container_id')!=original['Id']
                or removing.get('intent_digest')!=intent['digest']):
            raise ValueError('private_retirement_changed_removal_intent')
        try:actual=engine.inspect(original['Id'])
        except DockerEngineError as error:
            if error.status!=404 or removing is None:raise
            _save(root,done.name,{'kind':'PrivateRuntimeResourceRemoved','container_id':original['Id'],
                'intent_digest':intent['digest'],'actual_inspection_status':404})
            continue
        if (actual.get('Id')!=original['Id'] or actual.get('Image')!=original.get('Image')
                or actual.get('Config')!=original.get('Config') or actual.get('HostConfig')!=original.get('HostConfig')
                or actual.get('Mounts')!=original.get('Mounts')):
            raise ValueError('private_retirement_changed_actual_resource')
        if name=='keeper' and actual.get('State',{}).get('Running') is True:
            engine.request('POST','/containers/'+original['Id']+'/stop?t=1',timeout=5)
            actual=engine.inspect(original['Id'])
        if actual.get('State',{}).get('Running') is not False:
            raise RuntimeError('private_retirement_original_resource_not_stopped')
        if name=='worker' and actual['State'].get('ExitCode')!=closure['actual_exit_code']:
            raise ValueError('private_retirement_changed_worker_exit')
        if removing is None:
            _save(root,started.name,{'kind':'PrivateRuntimeResourceRemoving','container_id':original['Id'],
                'intent_digest':intent['digest'],'inspection':actual})
        # Never force running processes or let Docker delete anonymous volumes.
        engine.request('DELETE','/containers/'+original['Id']+'?force=false&v=false')
        _save(root,done.name,{'kind':'PrivateRuntimeResourceRemoved','container_id':original['Id'],
            'intent_digest':intent['digest'],'actual_delete_acknowledged':True})
    done=root/'volume-removed.json';started=root/'volume-removing.json'
    if not done.exists():
        removing=_controller_record(started) if started.exists() else None
        if removing is not None and (removing.get('volume_name')!=volume['Name']
                or removing.get('intent_digest')!=intent['digest']):
            raise ValueError('private_retirement_changed_volume_intent')
        try:actual=engine.inspect_volume(volume['Name'])
        except DockerEngineError as error:
            if error.status!=404 or removing is None:raise
            actual=None
        if actual is not None:
            if actual!=volume:raise ValueError('private_retirement_changed_original_volume')
            if removing is None:
                _save(root,started.name,{'kind':'PrivateRuntimeVolumeRemoving','volume_name':volume['Name'],
                    'intent_digest':intent['digest']})
            engine.remove_volume(volume['Name'])
        _save(root,done.name,{'kind':'PrivateRuntimeVolumeRemoved','volume_name':volume['Name'],
            'intent_digest':intent['digest'],'actual_inspection_status':404 if actual is None else 200})
    receipt=_controller_record(done)
    if receipt.get('volume_name')!=volume['Name'] or receipt.get('intent_digest')!=intent['digest']:
        raise ValueError('private_retirement_changed_volume_receipt')
    return _save(root,'retirement-completion.json',{'kind':'OpaquePrivateRetirementCompletion',
        'grant_digest':grant['digest'],'reference_digest':reference['digest'],
        'worker_id':worker['Id'],'keeper_id':keeper['Id'],'run_volume':volume['Name'],
        'original_runtime_resources_released':True,'private_archive_preserved':True,
        'qualification_issued':False})


def main():
    os.umask(0o077)
    from skillloop.protection.authority import ProtectionAuthority
    action=read_owned('/assignment/action.json',uid=21004,gid=21004,limit=262144)
    fields={'kind','session_key','campaign_id','opaque_ref','factory_ref','launch_action_digest',
            'intent_digest','digest'}
    import re
    if (set(action)!=fields or action.get('kind')!='FormalPrivateRetirementAuthorization'
            or action['digest']!=os.environ.get('SKILLLOOP_PRIVATE_ACTION_DIGEST')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',action['launch_action_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',action['intent_digest'])
            or not re.fullmatch(r'private-run-[0-9a-f]{32}',action['opaque_ref'])):
        raise ValueError('private_retirement_frozen_gate_action')
    authority=ProtectionAuthority(Path('/private-authority'),readonly=True)
    authority.resolve_formal_bundle(campaign=action['campaign_id'],opaque_ref=action['factory_ref'])
    pins=authority.formal_session_identity(action['session_key'])
    if pins.get('intent_digest')!=action['intent_digest'] or pins.get('campaign')!=action['campaign_id']:
        raise ValueError('private_retirement_original_intent')
    authorize_retirement(authority=authority,session_key=action['session_key'],
        mapping_path='/session-projection/'+action['launch_action_digest'][7:]+'.launch.json',
        completion_path='/private-completion/'+action['opaque_ref']+'.json',
        task_review_path='/task-reviews/'+action['intent_digest'][7:]+'.json',
        archive_review_path='/archive-reviews/'+action['intent_digest'][7:]+'.archive.json',
        output_directory='/retirement-grants')


if __name__=='__main__':main()
