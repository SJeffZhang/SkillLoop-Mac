"""Independent Gate rederives one formal task from preserved raw evidence.

This receipt permits custody retirement. Whole-campaign reduction and issuer
admission still require every item in the complete RequiredRunManifest.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat

from skillloop.discovery.formal_evaluator import evaluate_capture
from skillloop.protocol import canonical_json_line, decode_json, digest_jcs


def read_owned(path, *, uid, gid, limit):
    from skillloop.runtime.archive_files import open_original, require_unchanged, identity
    path = Path(path)
    if type(limit) is not int or limit < 1:
        raise ValueError('formal_gate_read_capacity')
    parent = path.parent.lstat()
    if (not path.is_absolute() or path.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != uid or parent.st_gid != gid
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise PermissionError('formal_gate_directory_custody')
    fd = open_original(path)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1 or info.st_size > limit):
            raise PermissionError('formal_gate_file_custody')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(raw) != info.st_size or identity(info) != identity(after):
            raise ValueError('formal_gate_input_changed')
    require_unchanged(path, info, after)
    current_parent=path.parent.lstat()
    if any(getattr(parent,k)!=getattr(current_parent,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode')):
        raise ValueError('formal_gate_input_directory_changed')
    if len(raw) > limit:
        raise ValueError('formal_gate_input_capacity')
    value = decode_json(raw)
    if type(value) is not dict or value.get('digest') != digest_jcs({k:v for k,v in value.items() if k!='digest'}):
        raise ValueError('formal_gate_input_seal')
    return value


def review_task(*, assignment_path, evaluation_directory, raw_directory,
                snapshot_directory, output_directory):
    if os.geteuid() != 21005 or 21004 not in set(os.getgroups()) | {os.getegid()}:
        raise PermissionError('formal_independent_gate_role_required')
    owner=Path(assignment_path).parent.lstat().st_uid
    if owner not in {21001,21004}:raise PermissionError('formal_gate_assignment_owner')
    job = read_owned(assignment_path, uid=owner, gid=21004, limit=8388608)
    if (job.get('kind') != 'FormalEvaluatorAssignment'
            or set(job) != {'kind','entry','intent','capture','maximum_database_bytes',
                            'snapshot_wait_seconds','campaign_deadline','digest'}):
        raise ValueError('formal_gate_assignment_shape')
    private=job['entry'].get('kind')=='protected'
    if owner!=(21004 if private else 21001):
        raise PermissionError('formal_gate_private_assignment_custody')
    output_gid=21004 if private else 21001
    intent = job['intent']
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}',intent['digest'])
            or intent['digest'] != digest_jcs({k:v for k,v in intent.items() if k!='digest'})):
        raise ValueError('formal_gate_intent_identity')
    deadline = datetime.fromisoformat(job['campaign_deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or datetime.now(timezone.utc) >= deadline:
        raise TimeoutError('formal_gate_original_clock_expired')
    original = read_owned(Path(evaluation_directory)/(intent['digest'][7:]+'.json'),
                          uid=21004,gid=21004,limit=16777216)
    rebuilt = evaluate_capture(entry=job['entry'], intent=intent, capture=job['capture'],
        run_directory=raw_directory, snapshot_directory=Path(snapshot_directory)/intent['digest'][7:],
        output_directory=None, maximum_database_bytes=job['maximum_database_bytes'], review_only=True)
    if original != rebuilt:
        raise ValueError('formal_gate_independent_reconstruction_mismatch')
    if datetime.now(timezone.utc) >= deadline:
        raise TimeoutError('formal_gate_review_overran_original_clock')
    raw_grant=read_owned(Path(raw_directory)/'evaluator-read-grant.json',uid=owner,gid=21004,limit=2097152)
    receipt = {'kind':'FormalTaskEvidenceReview','entry_digest':job['entry']['digest'],
        'intent_digest':intent['digest'],'assignment_digest':job['digest'],
        'evaluation_digest':original['digest'],'execution_record_digest':original['execution_record']['digest'],
        'runtime_capture_digest':original['runtime_capture_digest'],
        'authority_snapshot_digest':original['authority_snapshot_digest'],
        'runtime_read_grant_digest':raw_grant['digest'],
        'archive_policy_digest':job['entry']['config']['durable_task_archive_policy_digest'],
        'image':job['entry']['config']['mac_runtime_image'],
        'deployment_epoch':job['entry']['config']['deployment_epoch'],
        'business_closure_digest':job['capture']['business_closure']['digest'],
        'evidence_complete':True,'gate_uid':21005,'qualification_issued':False,
        'review_completed_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
    receipt['digest'] = digest_jcs(receipt)
    output = Path(output_directory)
    info = output.lstat()
    if (not output.is_absolute() or output.is_symlink() or info.st_uid!=21005
            or info.st_gid!=output_gid or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('formal_gate_output_custody')
    path = output/(intent['digest'][7:]+'.json')
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,output_gid);os.fchmod(stream.fileno(),0o640)
        stream.write(canonical_json_line(receipt));stream.flush();os.fsync(stream.fileno())
    fd = os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return receipt


def review_archive(*,archive_directory,original_review_directory,output_directory,intent_digest,
                   campaign_deadline,maximum_bytes,maximum_files):
    """Rederive durable byte custody against the actual earlier Task Gate."""
    import hashlib
    import sqlite3
    owner=Path(archive_directory).lstat().st_uid
    if owner not in {21001,21004} or os.geteuid()!=21005 or owner not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('formal_archive_independent_gate_uid')
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}',intent_digest)
            or type(maximum_bytes) is not int or not 1<=maximum_bytes<=2147483648
            or type(maximum_files) is not int or not 1<=maximum_files<=4096):
        raise ValueError('formal_archive_frozen_bounds')
    deadline=datetime.fromisoformat(campaign_deadline.replace('Z','+00:00'))
    def budget():
        if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
            raise TimeoutError('formal_archive_original_terminal_reserve')
    budget()
    root=Path(archive_directory)
    receipt=read_owned(root/'archive-receipt.json',uid=owner,gid=21005,limit=2097152)
    original=read_owned(Path(original_review_directory)/(intent_digest[7:]+'.json'),
        uid=21005,gid=owner,limit=262144)
    if (receipt.get('kind')!='DurableReviewedTaskArchive'
            or receipt.get('intent_digest')!=intent_digest or original.get('intent_digest')!=intent_digest
            or receipt.get('review_digest')!=original['digest']
            or original.get('kind')!='FormalTaskEvidenceReview' or original.get('gate_uid')!=21005
            or original.get('evidence_complete') is not True
            or receipt.get('independent_archive_review_complete') is not False
            or receipt.get('qualification_issued') is not False):
        raise ValueError('formal_archive_original_gate_binding')
    if receipt.get('policy_digest')!=original.get('archive_policy_digest'):
        raise ValueError('formal_archive_original_frozen_policy')
    if owner==21004:
        from skillloop.runtime.task_archive import resolve_private_archive_policy,validate_controller_archive_reference
        declaration=receipt.get('private_archive_declaration');policy=receipt.get('private_archive_policy')
        attestation=receipt.get('private_archive_mount_attestation')
        original_attestation=read_owned('/archive-mount/mount.json',uid=21001,gid=21004,limit=2097152)
        if (type(declaration) is not dict or type(policy) is not dict or type(attestation) is not dict
                or attestation!=original_attestation
                or declaration.get('digest')!=receipt['policy_digest']
                or declaration['digest']!=digest_jcs({k:v for k,v in declaration.items() if k!='digest'})
                or attestation.get('kind')!='PrivateArchiveMountAttestation'
                or attestation.get('digest')!=digest_jcs({k:v for k,v in attestation.items() if k!='digest'})
                or attestation.get('policy_digest')!=policy.get('digest')
                or attestation.get('deployment_epoch')!=original.get('deployment_epoch')):
            raise ValueError('formal_archive_private_policy_and_mount_proof')
        actual=attestation.get('inspection',{});volume=attestation.get('volume',{})
        action=actual.get('Config',{}).get('Labels',{}).get('skillloop.action','')
        if (policy!=resolve_private_archive_policy(declaration,action_digest=action)
                or policy.get('digest')!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
                or policy.get('controller_container_id')!='action-'+action
                or policy.get('deployment_epoch')!=original.get('deployment_epoch')
                or policy.get('image')!=original.get('image')
                or policy.get('campaign_deadline')!=campaign_deadline
                or type(policy.get('maximum_bytes')) is not int or policy['maximum_bytes']>maximum_bytes
                or type(policy.get('maximum_files')) is not int or policy['maximum_files']>maximum_files
                or policy.get('archive_volume')!=receipt.get('archive_volume')):
            raise ValueError('formal_archive_private_actual_action_binding')
        validate_controller_archive_reference(policy,private=True)
        config=actual.get('Config',{});host=actual.get('HostConfig',{})
        if (not re.fullmatch(r'[0-9a-f]{64}',actual.get('Id',''))
                or actual.get('Image')!=policy['image'] or config.get('User')!='21004:21004'
                or config.get('Entrypoint')!=['python'] or config.get('Cmd')!=['-m','skillloop.protection.formal_session']
                or config.get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']
                or config.get('Labels',{}).get('skillloop.role')!='private_session'
                or actual.get('State',{}).get('Running') is not False
                or host.get('NetworkMode')!='none' or host.get('ReadonlyRootfs') is not True
                or host.get('CapDrop')!=['ALL'] or host.get('LogConfig',{}).get('Type')!='none'
                or not {'21001','21005'}<=set(host.get('GroupAdd',[]))
                or 'no-new-privileges' not in host.get('SecurityOpt',[])
                or volume.get('Name')!=policy['archive_volume'] or volume.get('Driver')!='local'
                or volume.get('Options') not in (None,{})
                or volume.get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']
                or len([m for m in actual.get('Mounts',[]) if m.get('Type')=='volume'
                    and m.get('Name')==policy['archive_volume'] and m.get('Destination')==policy['archive_root']
                    and m.get('RW') is True])!=1
                or len([m for m in host.get('Mounts',[]) if m.get('Type')=='volume'
                    and m.get('Source')==policy['archive_volume'] and m.get('Target')==policy['archive_root']
                    and m.get('ReadOnly') is False])!=1):
            raise ValueError('formal_archive_private_original_persistent_process')
    creation=receipt.get('controller_creation_evidence')
    if creation is not None:
        from skillloop.runtime.task_archive import validate_controller_archive_reference
        from skillloop.runtime.evaluation_dispatch import _verify_role_process
        policy=receipt.get('controller_archive_policy')
        if (type(policy) is not dict or policy.get('kind')!='FrozenDurableTaskArchive'
                or policy.get('digest')!=receipt['policy_digest']
                or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
                or policy.get('image')!=original.get('image')
                or policy.get('deployment_epoch')!=original.get('deployment_epoch')
                or policy.get('archive_volume')!=receipt.get('archive_volume')
                or type(creation) is not dict or set(creation)!={'intent','created','inspection'}):
            raise ValueError('formal_archive_frozen_creation_evidence')
        pin=validate_controller_archive_reference(policy)
        if pin is None:raise ValueError('formal_archive_named_creation_required')
        intent_record,created,actual=(creation[k] for k in ('intent','created','inspection'))
        for record,kind in ((intent_record,'WholeRoleCreateIntent'),(created,'WholeRoleCreated')):
            if (record.get('kind')!=kind or record.get('role')!='controller'
                    or record.get('digest')!=digest_jcs({k:v for k,v in record.items() if k!='digest'})):
                raise ValueError('formal_archive_original_creation_seals')
        config=intent_record['configuration']
        _verify_role_process(actual,created['id'],config,config['HostConfig']['Mounts'],controller_engine_bind=True)
        if (intent_record.get('operation')!=pin['operation_id']
                or intent_record.get('container_name')!=policy['controller_container_id'][5:]
                or actual.get('Name')!='/'+intent_record['container_name']
                or actual.get('Config')!=created.get('inspection',{}).get('Config')
                or actual.get('HostConfig')!=created.get('inspection',{}).get('HostConfig')
                or actual.get('Image')!=policy['image'] or actual['Config'].get('User')!='21001:21001'
                or actual['Config'].get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']
                or actual['State'].get('Running') is not True
                or not any(m.get('Type')=='volume' and m.get('Name')==receipt['archive_volume']
                    and m.get('Destination')==policy['archive_root'] and m.get('RW') is True
                    for m in actual.get('Mounts',[]))):
            raise ValueError('formal_archive_original_creation_and_mount_chain')
    index={};total=0;nodes=0
    for parent,dirs,files in os.walk(root,followlinks=False):
        budget()
        for name in dirs+files:
            nodes+=1
            # Two category roots and the receipt are archive-only entries;
            # the original export bound already includes nested source dirs.
            if nodes>maximum_files+3:raise ValueError('formal_archive_file_capacity')
            path=Path(parent)/name;info=path.lstat()
            if (path.is_symlink() or info.st_uid!=owner or info.st_gid!=21005
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                    or stat.S_IMODE(info.st_mode)!=(0o750 if stat.S_ISDIR(info.st_mode) else 0o640)):
                raise PermissionError('formal_archive_actual_read_grant')
            if stat.S_ISDIR(info.st_mode) or path==root/'archive-receipt.json':continue
            total+=info.st_size
            if total>maximum_bytes or info.st_blocks*512<info.st_size:
                raise ValueError('formal_archive_actual_capacity_or_disk_blocks')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            h=hashlib.sha256()
            with os.fdopen(fd,'rb') as stream:
                for data in iter(lambda:stream.read(1048576),b''):budget();h.update(data)
                after=os.fstat(stream.fileno())
            if (after.st_size,after.st_mtime_ns)!=(info.st_size,info.st_mtime_ns):
                raise ValueError('formal_archive_bytes_changed_during_review')
            index[path.relative_to(root).as_posix()]={'bytes':info.st_size,'digest':'sha256:'+h.hexdigest()}
    files=receipt.get('files')
    if (type(files) is not list or any(type(row) is not dict or set(row)!={'path','bytes','digest'} for row in files)
            or len({row['path'] for row in files})!=len(files)
            or {row['path']:{'bytes':row['bytes'],'digest':row['digest']} for row in files}!=index
            or receipt.get('total_bytes')!=total):
        raise ValueError('formal_archive_complete_inventory_mismatch')
    grant=read_owned(root/'runtime/evaluator-read-grant.json',uid=owner,gid=21005,limit=2097152)
    snapshot=read_owned(root/'authority/snapshot.json',uid=owner,gid=21005,limit=262144)
    capture=read_owned(root/'runtime/runtime-capture.json',uid=owner,gid=21005,limit=8388608)
    evaluation=read_owned(root/'evaluation.json',uid=owner,gid=21005,limit=16777216)
    copied_review=read_owned(root/'gate.json',uid=owner,gid=21005,limit=262144)
    runtime_index={name[8:]:pin for name,pin in index.items()
        if name.startswith('runtime/') and name!='runtime/evaluator-read-grant.json'}
    if (copied_review!=original or grant['digest']!=original['runtime_read_grant_digest']
            or runtime_index!=grant['files'] or grant.get('intent_digest')!=intent_digest
            or capture['digest']!=original['runtime_capture_digest']
            or evaluation['digest']!=original['evaluation_digest']
            or evaluation['execution_record']['digest']!=original['execution_record_digest']
            or snapshot['digest']!=original['authority_snapshot_digest']
            or index.get('authority/authority.db')!={'bytes':snapshot['database_size_bytes'],
                                                    'digest':snapshot['database_digest']}):
        raise ValueError('formal_archive_original_evidence_chain_mismatch')
    db=sqlite3.connect((root/'authority/authority.db').absolute().as_uri()+'?mode=ro&immutable=1',uri=True,timeout=2)
    try:
        db.set_progress_handler(lambda: int((deadline-datetime.now(timezone.utc)).total_seconds()<=120),1000)
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
            raise ValueError('formal_archive_database_integrity')
    finally:db.close()
    budget()
    result={'kind':'FormalTaskArchiveReview','intent_digest':intent_digest,'entry_digest':original['entry_digest'],
        'task_review_digest':original['digest'],'archive_receipt_digest':receipt['digest'],
        'inventory_digest':digest_jcs(files),'complete':True,'gate_uid':21005,
        'qualification_issued':False,'restore_executed':False,
        'review_completed_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
    result['digest']=digest_jcs(result)
    output=Path(output_directory);info=output.lstat()
    if (not output.is_absolute() or output.is_symlink() or info.st_uid!=21005
            or info.st_gid!=owner or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('formal_archive_gate_output_custody')
    fd=os.open(output/(intent_digest[7:]+'.archive.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,owner);os.fchmod(stream.fileno(),0o640)
        stream.write(canonical_json_line(result));stream.flush();os.fsync(stream.fileno())
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return result


def main():
    os.umask(0o077)
    import sys
    if sys.argv[1:]==['--archive']:
        review_archive(archive_directory='/archive/'+os.environ['SKILLLOOP_ARCHIVE_INTENT'][7:],
            original_review_directory='/original-reviews',
            output_directory='/reviews',intent_digest=os.environ['SKILLLOOP_ARCHIVE_INTENT'],
            campaign_deadline=os.environ['SKILLLOOP_ARCHIVE_DEADLINE'],
            maximum_bytes=int(os.environ['SKILLLOOP_ARCHIVE_MAX_BYTES']),
            maximum_files=int(os.environ['SKILLLOOP_ARCHIVE_MAX_FILES']))
        return
    if sys.argv[1:]:raise ValueError('formal_gate_entry_arguments')
    private=os.environ.get('SKILLLOOP_PRIVATE_ACTION_DIGEST')
    if private and os.path.lexists('/original-reviews'):
        action=read_owned('/assignment/assignment.json',uid=21004,gid=21004,limit=262144)
        if (set(action)!={'kind','intent_digest','campaign_deadline','maximum_bytes','maximum_files','digest'}
                or action.get('kind')!='FormalPrivateArchiveReview' or action['digest']!=private
                or action['maximum_bytes']+2097152>int(os.environ['SKILLLOOP_PRIVATE_MAX_EVIDENCE_BYTES'])):
            raise ValueError('private_archive_gate_frozen_action')
        review_archive(archive_directory='/archive/'+action['intent_digest'][7:],
            original_review_directory='/original-reviews',output_directory='/reviews',
            intent_digest=action['intent_digest'],campaign_deadline=action['campaign_deadline'],
            maximum_bytes=action['maximum_bytes'],maximum_files=action['maximum_files'])
        return
    if private:
        job=read_owned('/assignment/assignment.json',uid=21004,gid=21004,limit=8388608)
        if job['digest']!=private:raise ValueError('private_gate_frozen_assignment_digest')
    review_task(assignment_path='/assignment/assignment.json' if private else '/assignment/job.json', evaluation_directory='/evaluation',
                raw_directory='/raw', snapshot_directory='/authority', output_directory='/reviews')


if __name__ == '__main__':
    main()
