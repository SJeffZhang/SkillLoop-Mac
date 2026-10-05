"""Actual durable task export before the live tmpfs Keeper can be retired.

The archive is private Controller evidence, never a public report. Its receipt
establishes byte preservation on the configured persistent Docker disk volume;
whole-round Gate review and VM disaster recovery remain separate obligations.
"""
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs
from skillloop.runtime.archive_files import open_original,identity,require_unchanged,allocate_output


def validate_controller_archive_reference(policy,*,private=False):
    """Freeze a creation operation before Docker assigns its actual ID."""
    reference=policy.get('controller_container_id')
    creation=policy.get('controller_creation')
    if private:
        if creation is not None or type(reference) is not str or not re.fullmatch(r'action-sha256:[0-9a-f]{64}',reference):
            raise ValueError('task_archive_private_action_reference')
        return None
    if type(reference) is str and re.fullmatch(r'[0-9a-f]{64}',reference):
        if creation is not None:raise ValueError('task_archive_duplicate_controller_reference')
        return None
    if (type(creation) is not dict or set(creation)!={'operation_id','journal_directory'}
            or type(creation['operation_id']) is not str
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',creation['operation_id'])
            or type(creation['journal_directory']) is not str
            or not Path(creation['journal_directory']).is_absolute()
            or str(Path(creation['journal_directory']))!=creation['journal_directory']
            or '..' in Path(creation['journal_directory']).parts
            or reference!='name:skillloop-controller-'+digest_jcs(creation['operation_id'])[7:31]):
        raise ValueError('task_archive_frozen_original_controller_creation')
    return creation


def archive_reviewed_task(*,entry,intent,capture,review,policy_path,sources,engine=None,mount_attestation_path=None):
    private=entry.get('kind')=='protected'
    owner=21004 if private else 21001
    if os.geteuid()!=owner:raise PermissionError('task_archive_actual_custodian_required')
    policy=read_owned(policy_path,uid=21010,gid=owner,limit=262144)
    fields={'kind','deployment_epoch','image','controller_container_id','archive_volume',
            'archive_root','maximum_bytes','maximum_files','timeout_seconds','campaign_deadline','digest'}
    creation=validate_controller_archive_reference(policy,private=private)
    if (set(policy)!=fields|({'controller_creation'} if creation is not None else set()) or policy['kind']!='FrozenDurableTaskArchive'
            or policy['digest']!=entry['config'].get('durable_task_archive_policy_digest')
            or policy['deployment_epoch']!=intent['deployment_epoch']
            or policy['image']!=entry['config']['mac_runtime_image']
            or type(policy['maximum_bytes']) is not int or not 1<=policy['maximum_bytes']<=2147483648
            or type(policy['maximum_files']) is not int or not 1<=policy['maximum_files']<=4096
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=60):
        raise ValueError('task_archive_frozen_policy')
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
        raise TimeoutError('task_archive_original_terminal_clock')
    started=time.monotonic()
    def budget():
        if time.monotonic()-started>policy['timeout_seconds'] or datetime.now(timezone.utc)>=deadline:
            raise TimeoutError('task_archive_original_export_budget_exhausted')
    root=Path(policy['archive_root']);info=root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=owner or info.st_gid!=21005 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('task_archive_private_root')
    creation_evidence=None
    if private:
        if engine is not None or mount_attestation_path is None:
            raise PermissionError('private_archive_no_engine_access')
        attestation=read_owned(mount_attestation_path,uid=owner,gid=21004,limit=2097152)
        if (attestation.get('kind')!='PrivateArchiveMountAttestation'
                or attestation.get('policy_digest')!=policy['digest']
                or attestation.get('deployment_epoch')!=intent['deployment_epoch']):
            raise ValueError('private_archive_mount_attestation_binding')
        observed=datetime.fromisoformat(attestation['observed_at'].replace('Z','+00:00'))
        if observed.tzinfo is None or not 0<=(datetime.now(timezone.utc)-observed).total_seconds()<=60:
            raise ValueError('private_archive_mount_attestation_stale')
        container=attestation['inspection']
    else:
        if mount_attestation_path is not None:raise ValueError('development_archive_unexpected_attestation')
        if creation is None:
            container=engine.inspect(policy['controller_container_id'])
        else:
            from skillloop.runtime.protected_flow import _controller_record
            from skillloop.runtime.evaluation_dispatch import _verify_role_process
            filename='role-'+digest_jcs({'role':'controller','operation':creation['operation_id']})[7:]+'.json'
            original=_controller_record(Path(creation['journal_directory'])/filename)
            created=_controller_record(Path(creation['journal_directory'])/(filename+'.created'))
            if (original.get('kind')!='WholeRoleCreateIntent' or original.get('role')!='controller'
                    or original.get('operation')!=creation['operation_id']
                    or original.get('container_name')!=policy['controller_container_id'][5:]
                    or created.get('kind')!='WholeRoleCreated' or created.get('role')!='controller'
                    or created.get('id')!=created.get('inspection',{}).get('Id')):
                raise ValueError('task_archive_original_controller_created_chain')
            container=engine.inspect(created['id'])
            config=original['configuration']
            _verify_role_process(container,created['id'],config,config['HostConfig']['Mounts'],controller_engine_bind=True)
            if (container.get('Name')!='/'+original['container_name']
                    or container.get('Config')!=created['inspection'].get('Config')
                    or container.get('HostConfig')!=created['inspection'].get('HostConfig')
                    or container.get('Image')!=created['inspection'].get('Image')):
                raise ValueError('task_archive_actual_original_controller_changed')
            creation_evidence={'intent':original,'created':created,'inspection':container}
    if ((container.get('Config',{}).get('Labels',{}).get('skillloop.action')!=policy['controller_container_id'][7:] if private
            else container.get('Id')!=(creation_evidence['created']['id'] if creation_evidence else policy['controller_container_id'])) or container.get('Image')!=policy['image']
            or container.get('Config',{}).get('User')!=str(owner)+':'+str(owner)
            or container.get('State',{}).get('Running') is not (False if private else True)
            or container.get('Config',{}).get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']):
        raise ValueError('task_archive_actual_controller_identity')
    mounted=[m for m in container.get('Mounts',[]) if m.get('Type')=='volume'
             and m.get('Name')==policy['archive_volume'] and m.get('Destination')==str(root) and m.get('RW') is True]
    requested_mounts=[m for m in container.get('HostConfig',{}).get('Mounts',[])
        if m.get('Type')=='volume' and m.get('Source')==policy['archive_volume']
        and m.get('Target')==str(root) and m.get('ReadOnly') is False
        and (private or not m.get('VolumeOptions',{}).get('Subpath'))]
    volume=attestation['volume'] if private else engine.inspect_volume(policy['archive_volume'])
    if (len(mounted)!=1 or len(requested_mounts)!=1 or volume.get('Name')!=policy['archive_volume']
            or volume.get('Driver')!='local' or volume.get('Options') not in (None,{})
            or volume.get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']):
        raise ValueError('task_archive_actual_persistent_volume_required')
    if type(sources) is not dict or set(sources)!={'runtime','authority','evaluation','gate'}:
        raise ValueError('task_archive_complete_sources_required')
    identities={'runtime':(owner,21004),'authority':(21003,21004),
                'evaluation':(21004,21004),'gate':(21005,owner)}
    paths=[];total=0;enumerated=0
    for category,value in sources.items():
        path=Path(value);uid,gid=identities[category]
        info=path.lstat()
        if (not path.is_absolute() or path.is_symlink() or info.st_uid!=uid or info.st_gid!=gid
                or stat.S_IMODE(info.st_mode)!=(0o750 if category in {'runtime','authority'} else 0o640)
                or (category in {'runtime','authority'}) is not stat.S_ISDIR(info.st_mode)):
            raise PermissionError('task_archive_source_custody:'+category)
        if category in {'runtime','authority'}:
            pending=[path]
            while pending:
                budget();parent=pending.pop()
                with os.scandir(parent) as children:
                    for child in children:
                        enumerated+=1
                        if enumerated>policy['maximum_files']:raise ValueError('task_archive_inventory_capacity')
                        item=Path(child.path);meta=child.stat(follow_symlinks=False)
                        if (meta.st_uid!=uid or meta.st_gid!=gid
                                or not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode))
                                or stat.S_IMODE(meta.st_mode)!=(0o750 if stat.S_ISDIR(meta.st_mode) else 0o640)):
                            raise PermissionError('task_archive_descendant_custody')
                        if stat.S_ISDIR(meta.st_mode):pending.append(item)
                        else:paths.append((category+'/'+item.relative_to(path).as_posix(),item,meta))
                        if len(paths)+len(pending)>policy['maximum_files']:
                            raise ValueError('task_archive_inventory_capacity')
        else:
            if not stat.S_ISREG(info.st_mode):raise PermissionError('task_archive_source_regular_file')
            paths.append((category+'.json',path,info))
    for _,_,meta in paths:total+=meta.st_size
    if len(paths)>policy['maximum_files'] or total>policy['maximum_bytes']:
        raise ValueError('task_archive_actual_export_capacity')
    # Recheck the source receipts against this exact already-reviewed task.
    runtime=read_owned(Path(sources['runtime'])/'runtime-capture.json',uid=owner,gid=21004,limit=8388608)
    authority=read_owned(Path(sources['authority'])/'snapshot.json',uid=21003,gid=21004,limit=262144)
    evaluation=read_owned(sources['evaluation'],uid=21004,gid=21004,limit=16777216)
    gate=read_owned(sources['gate'],uid=21005,gid=owner,limit=262144)
    if (runtime!=capture or gate!=review or authority.get('digest')!=review['authority_snapshot_digest']
            or authority.get('intent_digest')!=intent['digest']
            or evaluation.get('digest')!=review['evaluation_digest']
            or evaluation.get('execution_record',{}).get('digest')!=review['execution_record_digest']):
        raise ValueError('task_archive_exact_reviewed_sources')
    grant=read_owned(Path(sources['runtime'])/'evaluator-read-grant.json',uid=owner,gid=21004,limit=2097152)
    if (grant.get('kind')!=('PrivateEvaluatorReadGrant' if private else 'FormalEvaluatorReadGrant')
            or grant['digest']!=review.get('runtime_read_grant_digest')
            or grant.get('runtime_capture_digest')!=capture['digest']
            or grant.get('intent_digest')!=intent['digest']):
        raise ValueError('task_archive_original_raw_read_inventory')
    fs=os.statvfs(root)
    if fs.f_bavail*fs.f_frsize<2147483648+total+1048576:
        raise OSError('task_archive_real_disk_floor')
    target=root/intent['digest'][7:]
    # A partial archive is an explicit recovery obligation, not an overwrite or
    # permission to run the victim again.
    target.mkdir(mode=0o700)
    inventory=[]
    for relative,source,meta in sorted(paths,key=lambda row:row[0]):
        budget();destination=target/relative;destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        source_fd=open_original(source)
        with os.fdopen(source_fd,'rb') as reader:
            before=os.fstat(reader.fileno())
            if identity(before)!=identity(meta):
                raise ValueError('task_archive_source_changed_before_copy')
            target_fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(target_fd,'wb') as writer:
                budget();allocate_output(writer.fileno(),meta.st_size);budget()
                checksum=hashlib.sha256();copied=0
                for block in iter(lambda:reader.read(1048576),b''):
                    budget();copied+=len(block)
                    if copied>meta.st_size:raise ValueError('task_archive_source_grew')
                    checksum.update(block);writer.write(block)
                writer.flush();os.fsync(writer.fileno());after=os.fstat(reader.fileno())
                require_unchanged(source,meta,after)
                if copied!=meta.st_size:
                    raise ValueError('task_archive_source_changed_during_copy')
        check=hashlib.sha256()
        with destination.open('rb') as stream:
            for block in iter(lambda:stream.read(1048576),b''):budget();check.update(block)
        physical=destination.lstat()
        if check.digest()!=checksum.digest() or physical.st_blocks*512<physical.st_size:
            raise ValueError('task_archive_actual_disk_bytes_unverified')
        inventory.append({'path':relative,'bytes':copied,'digest':'sha256:'+checksum.hexdigest()})
    runtime_index={row['path'][8:]:{'bytes':row['bytes'],'digest':row['digest']} for row in inventory
                   if row['path'].startswith('runtime/') and row['path']!='runtime/evaluator-read-grant.json'}
    databases=[row for row in inventory if row['path']=='authority/authority.db']
    if (runtime_index!=grant.get('files') or len(databases)!=1
            or databases[0]['digest']!=authority.get('database_digest')
            or databases[0]['bytes']!=authority.get('database_size_bytes')):
        raise ValueError('task_archive_reviewed_bytes_changed_after_gate')
    receipt={'kind':'DurableReviewedTaskArchive','intent_digest':intent['digest'],
        'entry_digest':entry['digest'],'review_digest':review['digest'],'policy_digest':policy['digest'],
        'archive_volume':volume['Name'],'archive_directory':str(target),'files':inventory,'total_bytes':total,
        'persistent_disk_bytes_verified':True,'independent_archive_review_complete':False,
        'qualification_issued':False,'elapsed_seconds':time.monotonic()-started}
    if creation_evidence is not None:
        receipt['controller_creation_evidence']=creation_evidence
        receipt['controller_archive_policy']=policy
    receipt['digest']=digest_jcs(receipt);budget()
    fd=os.open(target/'archive-receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(canonical_json_line(receipt));stream.flush();os.fsync(stream.fileno())
    # Grant this exact completed leaf to the independent Gate. The archive
    # volume root is Gate-readable; no source or DB write grant moves.
    for parent,dirs,files in os.walk(target,topdown=False):
        for name in files:
            item=Path(parent)/name
            os.chown(item,-1,21005);os.chmod(item,0o640)
        os.chown(parent,-1,21005);os.chmod(parent,0o750)
    for parent,_,_ in os.walk(target,topdown=False):
        budget();fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    budget()
    return receipt


def attest_private_archive_mount(*,policy,engine,output_directory,container_id):
    """Controller records actual storage only; it never opens private evidence."""
    from skillloop.runtime.docker_api import DockerEngine
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:
        raise PermissionError('private_archive_actual_controller_engine')
    if (type(policy) is not dict or policy.get('kind')!='FrozenDurableTaskArchive'
            or policy.get('digest')!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})):
        raise ValueError('private_archive_frozen_mount_policy')
    actual=engine.inspect(container_id)
    volume=engine.inspect_volume(policy['archive_volume'])
    if (not re.fullmatch(r'[0-9a-f]{64}',container_id) or actual.get('Id')!=container_id
            or policy['controller_container_id']!='action-'+actual.get('Config',{}).get('Labels',{}).get('skillloop.action','')
            or actual.get('Image')!=policy['image']
            or actual.get('Config',{}).get('User')!='21004:21004'
            or actual.get('State',{}).get('Running') is not False
            or actual.get('Config',{}).get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']
            or volume.get('Name')!=policy['archive_volume'] or volume.get('Driver')!='local'
            or volume.get('Options') not in (None,{})
            or volume.get('Labels',{}).get('skillloop.deployment_epoch')!=policy['deployment_epoch']
            or len([m for m in actual.get('Mounts',[]) if m.get('Type')=='volume'
                and m.get('Name')==policy['archive_volume'] and m.get('Destination')==policy['archive_root']
                and m.get('RW') is True])!=1):
        raise ValueError('private_archive_actual_evaluator_persistent_mount')
    directory=Path(output_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(21001,21004,0o750)):
        raise PermissionError('private_archive_attestation_custody')
    receipt={'kind':'PrivateArchiveMountAttestation','policy_digest':policy['digest'],
        'deployment_epoch':policy['deployment_epoch'],'inspection':actual,'volume':volume,
        'observed_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
    receipt['digest']=digest_jcs(receipt)
    fd=os.open(directory/'mount.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,21004);os.fchmod(stream.fileno(),0o640)
        stream.write(canonical_json_line(receipt));stream.flush();os.fsync(stream.fileno())
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return receipt
