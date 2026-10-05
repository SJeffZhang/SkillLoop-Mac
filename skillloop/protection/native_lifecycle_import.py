"""Admin imports original host process records into independent Gate custody."""
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import stat
import time
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import decode_json,digest_jcs,canonical_json_line
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.archive_files import open_original,require_unchanged,allocate_output


def import_lifecycle(assignment_path):
    if os.geteuid()!=21010 or 21005 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('native_lifecycle_actual_admin_import')
    job=read_owned(assignment_path,uid=21001,gid=21010,limit=262144)
    fields={'kind','campaign_id','deployment_epoch','opaque_ref','host_admin_uid','export_digest',
        'input_directory','output_directory','deadline','maximum_bytes','timeout_seconds','digest'}
    if (set(job)!=fields or job['kind']!='FrozenNativeLifecycleImport'
            or type(job['host_admin_uid']) is not int or job['host_admin_uid']<1
            or type(job['maximum_bytes']) is not int or not 8388608<=job['maximum_bytes']<=75497472
            or type(job['timeout_seconds']) is not int or not 1<=job['timeout_seconds']<=60):
        raise ValueError('native_lifecycle_original_import_policy')
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'));started=time.monotonic()
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=job['timeout_seconds']+120:
        raise TimeoutError('native_lifecycle_original_import_clock')
    def budget():
        if time.monotonic()-started>=job['timeout_seconds'] or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
            raise TimeoutError('native_lifecycle_original_import_clock')
    # Host UID is provenance, never Linux authorization. A trusted deployment
    # transfer must place unchanged bytes into Admin-only custody first; this
    # worker cannot read the host journal or chown foreign files itself.
    source=Path(job['input_directory']);info=source.lstat()
    if (not source.is_absolute() or source.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid,info.st_gid)!=(21010,21010) or stat.S_IMODE(info.st_mode)!=0o700
            or set(os.listdir(source))!={'export.json','evidence.json','development-backend.log'}):
        raise PermissionError('native_lifecycle_original_host_export_custody')
    def original(name,limit,expected=None):
        path=source/name;fd=open_original(path)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if ((before.st_uid,before.st_gid)!=(21010,21010) or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>limit):
                raise PermissionError('native_lifecycle_original_host_file')
            raw=stream.read(limit+1);budget();require_unchanged(path,before,os.fstat(stream.fileno()))
        if len(raw)>limit or (expected is not None and
                (expected.get('bytes')!=len(raw) or expected.get('digest')!='sha256:'+hashlib.sha256(raw).hexdigest())):
            raise ValueError('native_lifecycle_original_host_file_digest')
        return raw
    receipt=decode_json(original('export.json',262144))
    if (set(receipt)!={'kind','host_admin_uid','campaign_id','deployment_epoch','deadline','files','exported_at','qualification_issued','digest'}
            or receipt.get('kind')!='NativeHostLifecycleExport' or receipt.get('digest')!=job['export_digest']
            or receipt['digest']!=digest_jcs({k:v for k,v in receipt.items() if k!='digest'})
            or any(receipt[k]!=job[k] for k in ('campaign_id','deployment_epoch','host_admin_uid','deadline'))
            or receipt['qualification_issued'] is not False
            or set(receipt['files'])!={'evidence.json','development-backend.log'}):
        raise ValueError('native_lifecycle_original_export_identity')
    exported=datetime.fromisoformat(receipt['exported_at'].replace('Z','+00:00'))
    if exported.tzinfo is None or not exported<=datetime.now(timezone.utc)<deadline:
        raise ValueError('native_lifecycle_original_export_time')
    for row in receipt['files'].values():
        if type(row) is not dict or set(row)!={'bytes','digest'} or type(row['bytes']) is not int or row['bytes']<0:
            raise ValueError('native_lifecycle_original_export_inventory')
    if sum(row['bytes'] for row in receipt['files'].values())>job['maximum_bytes']:
        raise ValueError('native_lifecycle_original_import_capacity')
    evidence=decode_json(original('evidence.json',8388608,receipt['files']['evidence.json']))
    if (evidence.get('kind')!='AdminNativeLifecycleEvidence'
            or set(evidence)!={'kind','campaign_id','opaque_ref','development','private','digest'}
            or evidence['digest']!=digest_jcs({k:v for k,v in evidence.items() if k!='digest'})
            or evidence['campaign_id']!=job['campaign_id'] or evidence['opaque_ref']!=job['opaque_ref']
            or evidence['development']['stopped']['backend_log_digest']!=receipt['files']['development-backend.log']['digest']):
        raise ValueError('native_lifecycle_original_import_evidence')
    # Structural Gate verification is reused before copying, with the actual
    # supervisor policy itself as the binding record. It is never a Gate pass.
    from skillloop.protection.model_lifecycle_gate import _start,_sealed
    dp=evidence['development']['start']['intent']['policy'];pp=evidence['private']['intent']['policy']
    record={k:dp[k] for k in ('campaign_id','deployment_epoch','config_digest','source_index_digest')}
    record['deadline']=job['deadline'];record['config']={k:dp[k] for k in ('tokenizer_hashes','model_manifest_digest')}
    _start(evidence['development']['start'],'dev',record);_start(evidence['private'],'protected',record)
    if dp['host_admin_uid']!=job['host_admin_uid'] or pp['host_admin_uid']!=job['host_admin_uid']:
        raise ValueError('native_lifecycle_original_host_admin_binding')
    _sealed(evidence['development']['stop_intent'],'NativeBackendStopIntent')
    _sealed(evidence['development']['stopped'],'NativeBackendStopped')
    output=_directory(job['output_directory'],21010,21005,0o750)
    if any(output.iterdir()):raise RuntimeError('native_lifecycle_partial_import_preserve_original')
    # Preserve intent first: partial custody transfer never silently repeats.
    intent={'kind':'AdminNativeLifecycleImportIntent','assignment_digest':job['digest'],
        'export_digest':receipt['digest'],'started_at':datetime.now(timezone.utc).isoformat(),
        'automatic_reexecution_allowed':False};intent['digest']=digest_jcs(intent)
    _publish(output/'import-intent.json',intent,21005)
    log_pin=receipt['files']['development-backend.log'];path=source/'development-backend.log'
    fd=open_original(path)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if (before.st_uid,before.st_gid)!=(21010,21010) or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size!=log_pin['bytes']:
            raise PermissionError('native_lifecycle_original_log_custody')
        target=os.open(output/'development-backend.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(target,'r+b') as destination:
            allocate_output(destination.fileno(),before.st_size)
            checksum=hashlib.sha256();size=0
            for block in iter(lambda:stream.read(1048576),b''):
                budget();size+=len(block)
                if size>log_pin['bytes']:raise ValueError('native_lifecycle_original_log_changed')
                checksum.update(block);destination.write(block)
            require_unchanged(path,before,os.fstat(stream.fileno()))
            if size!=log_pin['bytes'] or 'sha256:'+checksum.hexdigest()!=log_pin['digest']:
                raise ValueError('native_lifecycle_original_log_digest')
            destination.flush();os.fchown(destination.fileno(),-1,21005);os.fchmod(destination.fileno(),0o640);os.fsync(destination.fileno())
    budget();_publish(output/'evidence.json',evidence,21005)
    completion={'kind':'AdminNativeLifecycleImportCompletion','assignment_digest':job['digest'],
        'export_digest':receipt['digest'],'campaign_id':job['campaign_id'],'deployment_epoch':job['deployment_epoch'],
        'imported_at':datetime.now(timezone.utc).isoformat(),'gate_review_verified':False,'qualification_issued':False}
    completion['digest']=digest_jcs(completion);_publish(output/'import-completion.json',completion,21005)
    result={'kind':'OpaqueNativeLifecycleImported','campaign_public_ref':job['campaign_id'],
        'deployment_epoch':job['deployment_epoch'],'aggregate_status':'imported',
        'gate_review_verified':False,'qualification_issued':False}
    result['digest']=digest_jcs(result);return result
