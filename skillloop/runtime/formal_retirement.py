"""Retire exact Runtime resources only after real Gate-owned raw reconstruction."""
import os
from datetime import datetime,timezone
from pathlib import Path
import stat

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs
from skillloop.runtime.docker_api import DockerEngine


def retire_reviewed_task(*,entry,intent,capture,review_path,journal_directory,engine,role_processes,
                         archive_policy_path,archive_sources,archive_gate_policy,archive_gate_journal_directory,
                         archive_review_path):
    if os.geteuid()!=21001 or not isinstance(engine,DockerEngine):
        raise PermissionError('formal_retirement_controller_required')
    path=Path(review_path);parent=path.parent.lstat()
    if (not path.is_absolute() or path.parent.is_symlink() or parent.st_uid!=21005
            or parent.st_gid!=21001 or stat.S_IMODE(parent.st_mode)!=0o750):
        raise PermissionError('formal_retirement_gate_directory')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21005 or info.st_gid!=21001
                or stat.S_IMODE(info.st_mode)!=0o640 or info.st_size>262144):
            raise PermissionError('formal_retirement_gate_file')
        review=decode_json(stream.read(262145))
    closure=capture['business_closure']
    for value in (review,capture,closure,intent,entry):
        if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
            raise ValueError('formal_retirement_changed_evidence')
    if (review.get('kind')!='FormalTaskEvidenceReview' or review.get('gate_uid')!=21005
            or review.get('evidence_complete') is not True or review.get('qualification_issued') is not False
            or review['entry_digest']!=entry['digest'] or review['intent_digest']!=intent['digest']
            or review['runtime_capture_digest']!=capture['digest']
            or review['business_closure_digest']!=closure['digest']):
        raise ValueError('formal_retirement_independent_gate_binding')
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or info.st_uid!=21001
            or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('formal_retirement_journal_owner')
    def save(name,value):
        value['digest']=digest_jcs({k:v for k,v in value.items() if k!='digest'})
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(value));stream.flush();os.fsync(stream.fileno())
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    if (directory/'retirement-intent.json').exists():
        return recover_reviewed_retirement(entry=entry,intent=intent,review=review,
            archive_review_path=archive_review_path,journal_directory=directory,engine=engine)
    worker=engine.inspect(closure['stopped_container_id'])
    keeper=engine.inspect(closure['keeper_id'])
    volume=engine.inspect_volume(closure['run_volume'])
    for value,uid in ((worker,'21002:21002'),(keeper,'21001:21001')):
        if (value['Image']!=entry['config']['mac_runtime_image'] or value['Config']['User']!=uid
                or value['Config'].get('Labels',{}).get('skillloop.run_request')!=intent['run_request']['digest']):
            raise ValueError('formal_retirement_actual_resource_identity')
    if (worker['Id']!=closure['stopped_container_id'] or keeper['Id']!=closure['keeper_id']
            or worker['State']['Running'] or keeper['State']['Running'] is not True
            or worker['State']['ExitCode']!=closure['actual_exit_code']
            or volume['Name']!=closure['run_volume']
            or volume.get('Labels',{}).get('skillloop.run_request')!=intent['run_request']['digest']
            or not any(m.get('Name')==volume['Name'] and m.get('RW') is False for m in keeper['Mounts'])):
        raise ValueError('formal_retirement_live_custody_required')
    if type(role_processes) is not dict or set(role_processes)!={'protected_evaluator','gate'}:
        raise ValueError('formal_retirement_role_processes_required')
    role_inspections={}
    for role,uid in (('protected_evaluator','21004:21004'),('gate','21005:21005')):
        original=role_processes[role];actual=engine.inspect(original['Id'])
        if (actual['Id']!=original['Id'] or actual['Image']!=entry['config']['mac_runtime_image']
                or actual['Config']['User']!=uid or actual['State']['Running']
                or actual['State']['ExitCode']!=0 or original['State']['ExitCode']!=0
                or actual['Config'].get('Labels')!=original['Config'].get('Labels')
                or actual['Config'].get('Labels',{}).get('skillloop.role')!=role
                or actual['Config'].get('Labels',{}).get('skillloop.intent')!=intent['digest']
                or actual['HostConfig']['NetworkMode']!='none' or actual['HostConfig']['ReadonlyRootfs'] is not True):
            raise ValueError('formal_retirement_independent_role_identity')
        role_inspections[role]=actual
    from skillloop.runtime.task_archive import archive_reviewed_task
    archive=archive_reviewed_task(entry=entry,intent=intent,capture=capture,review=review,
        policy_path=archive_policy_path,sources=archive_sources,engine=engine)
    save('durable-export.json',archive)
    # The same Gate role reads the copied bytes independently. No Keeper or
    # source volume is removed if archive dispatch, rehash or DB review fails.
    from skillloop.runtime.evaluation_dispatch import dispatch_task_gate
    from skillloop.discovery.formal_task_gate import read_owned
    archive_process=dispatch_task_gate(entry=entry,intent=intent,policy=archive_gate_policy,
        journal_directory=archive_gate_journal_directory,engine=engine,archive_mode=True)
    archive_review=read_owned(archive_review_path,uid=21005,gid=21001,limit=262144)
    if (archive_review.get('kind')!='FormalTaskArchiveReview' or archive_review.get('gate_uid')!=21005
            or archive_review.get('complete') is not True or archive_review.get('qualification_issued') is not False
            or archive_review.get('intent_digest')!=intent['digest']
            or archive_review.get('entry_digest')!=entry['digest']
            or archive_review.get('task_review_digest')!=review['digest']
            or archive_review.get('archive_receipt_digest')!=archive['digest']
            or archive_review.get('inventory_digest')!=digest_jcs(archive['files'])):
        raise ValueError('formal_retirement_archive_gate_binding')
    # Once written, any lost Engine response requires explicit recovery. Never
    # infer that an absent container means this retirement completed correctly.
    save('retirement-intent.json',{'kind':'FormalTaskRetirementIntent','review_digest':review['digest'],
        'intent_digest':intent['digest'],'archive_receipt_digest':archive['digest'],
        'archive_review_digest':archive_review['digest'],'archive_gate_process':archive_process,
        'worker_id':worker['Id'],'keeper_id':keeper['Id'],
        'volume':volume['Name'],'started_at':datetime.now(timezone.utc).isoformat(),
        'original_deadline':archive_gate_policy['campaign_deadline'],'reserved_retirement_seconds':120,
        'role_inspections':role_inspections,'worker_inspection':worker,'keeper_inspection':keeper,'volume_inspection':volume})
    return recover_reviewed_retirement(entry=entry,intent=intent,review=review,
        archive_review_path=archive_review_path,journal_directory=directory,engine=engine)


def recover_reviewed_retirement(*,entry,intent,review,archive_review_path,journal_directory,engine):
    """Reconcile only the original, independently reviewed resource deletion."""
    from skillloop.runtime.protected_flow import _controller_record
    from skillloop.runtime.proposal_dispatch import _save
    from skillloop.discovery.formal_task_gate import read_owned
    from skillloop.runtime.docker_api import DockerEngineError
    from skillloop.protection.current_task import _directory
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('formal_retirement_actual_controller')
    root=_directory(journal_directory,21001,21001,0o700)
    original=_controller_record(root/'retirement-intent.json')
    archive=read_owned(archive_review_path,uid=21005,gid=21001,limit=262144)
    if (original.get('kind')!='FormalTaskRetirementIntent' or original.get('intent_digest')!=intent['digest']
            or original.get('review_digest')!=review['digest']
            or review.get('entry_digest')!=entry['digest'] or review.get('evidence_complete') is not True
            or archive.get('kind')!='FormalTaskArchiveReview' or archive.get('complete') is not True
            or archive.get('intent_digest')!=intent['digest'] or archive.get('entry_digest')!=entry['digest']
            or archive.get('task_review_digest')!=review['digest']
            or archive.get('digest')!=original.get('archive_review_digest')
            or archive.get('archive_receipt_digest')!=original.get('archive_receipt_digest')):
        raise ValueError('formal_retirement_original_archive_authorization')
    began=datetime.fromisoformat(original['started_at'])
    deadline=datetime.fromisoformat(original['original_deadline'].replace('Z','+00:00'))
    if (began.tzinfo is None or deadline.tzinfo is None or began>datetime.now(timezone.utc)
            or original.get('reserved_retirement_seconds')!=120):
        raise ValueError('formal_retirement_original_clock')
    completed=root/'retirement-completion.json'
    if completed.exists():
        value=_controller_record(completed)
        if (value.get('kind')!='FormalTaskRetirementCompletion' or value.get('intent_digest')!=intent['digest']
                or value.get('review_digest')!=review['digest'] or value.get('runtime_resources_released') is not True
                or value.get('archive_review_digest')!=archive['digest']):
            raise ValueError('formal_retirement_original_completion')
        return value
    resources=[('keeper',original['keeper_inspection']),('worker',original['worker_inspection'])]
    resources.extend((role,actual) for role,actual in sorted(original['role_inspections'].items()))
    resources.append(('archive-gate',original['archive_gate_process']))
    ids=[item['Id'] for _,item in resources]
    if len(set(ids))!=len(ids):raise ValueError('formal_retirement_duplicate_original_resource')
    stopped_keeper=None
    for name,pin in resources:
        begin=root/(name+'.removing.json');done=root/(name+'.removed.json')
        if done.exists():
            value=_controller_record(done)
            if value.get('container_id')!=pin['Id'] or value.get('retirement_digest')!=original['digest']:
                raise ValueError('formal_retirement_changed_resource_receipt')
            if name=='keeper':stopped_keeper=value.get('stopped_inspection')
            continue
        removing=_controller_record(begin) if begin.exists() else None
        if removing is not None and (removing.get('container_id')!=pin['Id']
                or removing.get('retirement_digest')!=original['digest']):
            raise ValueError('formal_retirement_changed_resource_intent')
        try:actual=engine.inspect(pin['Id'])
        except DockerEngineError as error:
            if error.status!=404 or removing is None:raise
            actual=None
        if actual is not None:
            if (actual.get('Id')!=pin['Id'] or actual.get('Image')!=pin.get('Image')
                    or actual.get('Config')!=pin.get('Config') or actual.get('HostConfig')!=pin.get('HostConfig')
                    or actual.get('Mounts')!=pin.get('Mounts')):
                raise ValueError('formal_retirement_changed_actual_resource')
            if name=='keeper' and actual['State']['Running']:
                engine.request('POST','/containers/'+pin['Id']+'/stop?t=1',timeout=5)
                actual=engine.inspect(pin['Id'])
            if actual['State']['Running'] or name!='keeper' and actual['State']['ExitCode']!=pin['State']['ExitCode']:
                raise RuntimeError('formal_retirement_original_stopped_resource_required')
            if removing is None:
                removing=_save(root,begin.name,{'kind':'FormalReviewedResourceRemoving','container_id':pin['Id'],
                    'retirement_digest':original['digest'],'stopped_inspection':actual})
            engine.request('DELETE','/containers/'+pin['Id']+'?force=false&v=false')
        value=_save(root,done.name,{'kind':'FormalReviewedResourceRemoved','container_id':pin['Id'],
            'retirement_digest':original['digest'],'stopped_inspection':removing['stopped_inspection'],
            'reconciled_actual_404':actual is None})
        if name=='keeper':stopped_keeper=value['stopped_inspection']
    volume=original['volume_inspection'];begin=root/'volume.removing.json';done=root/'volume.removed.json'
    if not done.exists():
        removing=_controller_record(begin) if begin.exists() else None
        if removing is not None and (removing.get('volume')!=volume['Name']
                or removing.get('retirement_digest')!=original['digest']):
            raise ValueError('formal_retirement_changed_volume_intent')
        try:actual=engine.inspect_volume(volume['Name'])
        except DockerEngineError as error:
            if error.status!=404 or removing is None:raise
            actual=None
        if actual is not None:
            if actual!=volume:raise ValueError('formal_retirement_changed_actual_volume')
            if removing is None:_save(root,begin.name,{'kind':'FormalReviewedVolumeRemoving',
                'volume':volume['Name'],'retirement_digest':original['digest']})
            engine.remove_volume(volume['Name'])
        _save(root,done.name,{'kind':'FormalReviewedVolumeRemoved','volume':volume['Name'],
            'retirement_digest':original['digest'],'reconciled_actual_404':actual is None})
    receipt=_controller_record(done)
    if receipt.get('volume')!=volume['Name'] or receipt.get('retirement_digest')!=original['digest']:
        raise ValueError('formal_retirement_changed_volume_receipt')
    ended=datetime.now(timezone.utc);elapsed=(ended-began).total_seconds()
    budget_closure=('within_original_budget' if ended<deadline and elapsed<=120
        else 'inconclusive_expired_budget_closure')
    return _save(root,completed.name,{'role_containers_removed':{k:v['Id'] for k,v in original['role_inspections'].items()},
        'kind':'FormalTaskRetirementCompletion','intent_digest':intent['digest'],'review_digest':review['digest'],
        'worker_id':original['worker_id'],'keeper_id':original['keeper_id'],'volume':volume['Name'],
        'stopped_keeper_inspection':stopped_keeper,'runtime_resources_released':True,'durable_export_preserved':True,
        'archive_receipt_digest':original['archive_receipt_digest'],'archive_review_digest':archive['digest'],
        'archive_gate_container_removed':original['archive_gate_process']['Id'],
        'independent_archive_review_complete':True,'qualification_issued':False,
        'completed_at':ended.isoformat(),'elapsed_seconds':elapsed,
        'original_deadline':original['original_deadline'],'budget_closure':budget_closure})
