"""Evaluator reconstructs a current private capture from role-owned evidence."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import decode_json,digest_jcs,validate_envelope
from skillloop.protection.current_task import _directory,_publish


def prepare_capture(*,authority,action,projection_directory,private_directory,handoff_directory,
                    completion_directory,raw_directory,assignment_directory,maximum_bytes,maximum_files,timeout_seconds):
    if (os.geteuid()!=21004 or authority.readonly or set(action)!=
            {'kind','launch_action_digest','campaign_id','maximum_database_bytes','snapshot_wait_seconds','digest'}
            or action['kind']!='FormalPrivateCapturePreparation'):
        raise PermissionError('private_capture_actual_evaluator_action')
    projection=_directory(projection_directory,21004,21004,0o750)
    mapping=read_owned(projection/(action['launch_action_digest'][7:]+'.launch.json'),uid=21004,gid=21004,limit=262144)
    launch=mapping['launch'];pins=authority.formal_session_identity(mapping['session_key'])
    delivery=read_owned(Path(private_directory)/(mapping['session_key'][7:]+'.json'),uid=21004,gid=21004,limit=8388608)
    entry,intent=delivery['entry'],delivery['intent'];config=entry['config']
    if (mapping.get('kind')!='PrivateRunLaunchMapping' or mapping.get('action_digest')!=action['launch_action_digest']
            or launch['campaign_id']!=action['campaign_id'] or pins['campaign']!=action['campaign_id']
            or pins.get('intent_digest')!=intent['digest'] or pins.get('entry_digest')!=entry['digest']):
        raise ValueError('private_capture_committed_current_assignment')
    with authority.connect() as db:
        state=db.execute('SELECT state FROM sessions WHERE key=?',(mapping['session_key'],)).fetchone()
    if state!=('delivered',):raise ValueError('private_capture_delivered_session_required')
    deadline=datetime.fromisoformat(delivery['campaign_deadline'].replace('Z','+00:00'));started=time.monotonic()
    maximum_files=min(maximum_files,config['maximum_runtime_evidence_files'])
    maximum_bytes=min(maximum_bytes,config['maximum_runtime_evidence_bytes'])
    if (type(maximum_bytes) is not int or not 1<=maximum_bytes<=20971520
            or type(maximum_files) is not int or not 1<=maximum_files<=4096
            or type(timeout_seconds) is not int or not 1<=timeout_seconds<=30
            or type(action['maximum_database_bytes']) is not int or not 1<=action['maximum_database_bytes']<=536870912
            or type(action['snapshot_wait_seconds']) is not int or not 1<=action['snapshot_wait_seconds']<=60
            or deadline.tzinfo is None):raise ValueError('private_capture_frozen_bounds')
    def budget():
        if time.monotonic()-started>=timeout_seconds or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
            raise TimeoutError('private_capture_original_clock')
    completion=read_owned(Path(completion_directory)/(launch['opaque_ref']+'.json'),uid=21001,gid=21004,limit=2097152)
    opaque=completion.get('business_closure',{});closure=opaque.get('closure',{});bound=opaque.get('binding',{})
    for value in (opaque,closure,bound):
        if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
            raise ValueError('private_capture_controller_closure_seal')
    actual=completion.get('inspection',{});worker=actual.get('Config',{})
    if (completion.get('kind')!='OpaquePrivateRuntimeCompletion' or completion.get('reference_digest')!=launch['digest']
            or opaque.get('kind')!='OpaquePrivateBusinessClosure' or opaque.get('reference_digest')!=launch['digest']
            or opaque.get('started_digest')!=completion.get('started_digest')
            or closure.get('intent_digest')!=bound['digest'] or bound.get('reference_digest')!=launch['digest']
            or bound.get('run_request',{}).get('digest')!=intent['run_request']['digest']
            or bound.get('binding',{}).get('body',{}).get('run_id')!=intent['binding']['body']['run_id']
            or closure.get('evidence_released') is not False
            or actual.get('Id')!=closure.get('stopped_container_id') or actual.get('Image')!=config['mac_runtime_image']
            or actual.get('State',{}).get('Running') is not False or worker.get('User')!='21002:21002'
            or worker.get('Labels',{}).get('skillloop.run_request')!=intent['run_request']['digest']):
        raise ValueError('private_capture_actual_stopped_runtime_and_fence')
    from skillloop.proxy.wire import validate_control
    cancellation=validate_control(closure['cancellation'])
    if (cancellation['kind']!='CancellationResult' or cancellation['body']['run_id']!=launch['run_id']
            or cancellation['body']['campaign_public_ref']!=intent['campaign_id']
            or cancellation['body']['effective_fence']!=2):raise ValueError('private_capture_actual_cancellation')
    transport=completion.get('handoff',{})
    helper=transport.get('inspection',{})
    if (transport.get('kind')!='OpaquePrivateHandoffCompletion'
            or transport.get('wait',{}).get('StatusCode')!=0
            or helper.get('State',{}).get('Running') is not False
            or helper.get('State',{}).get('ExitCode')!=0
            or helper.get('Image')!=config['mac_runtime_image']
            or helper.get('Config',{}).get('User')!='21002:21002'
            or helper.get('HostConfig',{}).get('NetworkMode')!='none'
            or helper.get('HostConfig',{}).get('ReadonlyRootfs') is not True
            or helper.get('HostConfig',{}).get('LogConfig',{}).get('Type')!='none'):
        raise ValueError('private_capture_actual_handoff_process')
    source=_directory(handoff_directory,21002,21004,0o750)
    handoff=read_owned(source/'handoff.json',uid=21002,gid=21004,limit=262144)
    packet=read_owned(source/'current-request.json',uid=21002,gid=21004,limit=8388608)
    if (handoff.get('kind')!='RuntimePrivateEvidenceHandoff' or handoff.get('complete') is not True
            or handoff.get('victim_reexecuted') is not False or handoff.get('packet_digest')!=packet['digest']
            or handoff.get('run_request_digest')!=intent['run_request']['digest']
            or packet.get('kind')!='FormalPrivateCurrentRuntimeRequest' or packet['request']!=intent['run_request']
            or packet['binding']!=intent['binding'] or packet['config']!=config
            or packet['mutation']!=delivery['runtime_materials']['mutation']):
        raise ValueError('private_capture_original_runtime_packet')
    lease=validate_envelope(packet['run_lease'])
    if lease['body']['run_id']!=launch['run_id'] or lease['body']['fencing_token']!=1:
        raise ValueError('private_capture_original_runtime_lease')
    target=_directory(raw_directory,21004,21004,0o750)
    assignments=_directory(assignment_directory,21004,21004,0o750)
    if any(target.iterdir()) or any(assignments.iterdir()):raise FileExistsError('private_capture_fresh_outputs_required')
    inventory={};total=0;enumerated=0;pending=[source]
    pin=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    while pending:
        budget();parent=pending.pop()
        with os.scandir(parent) as children:
            for child in children:
                budget();enumerated+=1
                if enumerated+3>maximum_files:raise ValueError('private_capture_file_capacity')
                path=Path(child.path);meta=child.stat(follow_symlinks=False);isdir=stat.S_ISDIR(meta.st_mode)
                if ((meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))!=(21002,21004,0o750 if isdir else 0o640)
                        or not (isdir or stat.S_ISREG(meta.st_mode)) or (not isdir and meta.st_nlink!=1)):
                    raise PermissionError('private_capture_handoff_descendant_custody')
                relative=path.relative_to(source).as_posix();destination=target/relative
                if isdir:destination.mkdir(mode=0o750);os.chmod(destination,0o750);pending.append(path);continue
                total+=meta.st_size
                if total+1048576>maximum_bytes:raise ValueError('private_capture_byte_capacity')
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as reader:
                    if pin(os.fstat(reader.fileno()))!=pin(meta):raise ValueError('private_capture_source_changed')
                    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();copied=0
                    with os.fdopen(fd,'wb') as writer:
                        for block in iter(lambda:reader.read(1048576),b''):
                            budget();copied+=len(block)
                            if copied>meta.st_size:raise ValueError('private_capture_source_grew')
                            h.update(block);writer.write(block)
                        os.fchown(writer.fileno(),-1,21004);os.fchmod(writer.fileno(),0o640);writer.flush();os.fsync(writer.fileno())
                    if copied!=meta.st_size or pin(os.fstat(reader.fileno()))!=pin(meta):raise ValueError('private_capture_source_changed_during_copy')
                inventory[relative]={'bytes':copied,'digest':'sha256:'+h.hexdigest()}
    original={k:v for k,v in inventory.items() if k!='handoff.json'}
    budget()
    if original!=handoff.get('files') or sum(v['bytes'] for v in original.values())!=handoff.get('total_bytes'):
        raise ValueError('private_capture_complete_handoff_inventory')
    result_path=target/'evidence/adapter-result.json'
    if not result_path.exists():raise RuntimeError('private_capture_missing_terminal_result_preserve_unknown')
    result=decode_json(result_path.read_bytes())
    closed={**closure,'intent_digest':intent['digest'],'opaque_closure_digest':opaque['digest']}
    closed['digest']=digest_jcs({k:v for k,v in closed.items() if k!='digest'})
    capture={'kind':'FormalRuntimeCapture','entry_digest':entry['digest'],'intent_digest':intent['digest'],
        'source_admission_digest':digest_jcs(entry['source_admission']),'approval_digest':launch['approval_digest'],
        'lease':lease,'trust_revision':launch['trust_revision'],'result':result,'business_closure':closed,
        'spending_state_digest':completion['spending_state_digest'],'runtime_handoff_digest':handoff['digest'],
        'evaluation_complete':False,'independent_gate_complete':False}
    capture['digest']=digest_jcs(capture);_publish(target/'runtime-capture.json',capture,21004)
    raw=(target/'runtime-capture.json').read_bytes();inventory['runtime-capture.json']={'bytes':len(raw),'digest':'sha256:'+hashlib.sha256(raw).hexdigest()};total+=len(raw)
    grant={'kind':'PrivateEvaluatorReadGrant','custodian_uid':21004,'evaluator_gid':21004,
        'intent_digest':intent['digest'],'runtime_capture_digest':capture['digest'],'business_closure_digest':closed['digest'],
        'files':inventory,'total_bytes':total,'independent_gate_complete':False,'evidence_released':False}
    grant['digest']=digest_jcs(grant);_publish(target/'evaluator-read-grant.json',grant,21004)
    job={'kind':'FormalEvaluatorAssignment','entry':entry,'intent':intent,'capture':capture,
        'maximum_database_bytes':action['maximum_database_bytes'],'snapshot_wait_seconds':action['snapshot_wait_seconds'],
        'campaign_deadline':delivery['campaign_deadline']}
    job['digest']=digest_jcs(job)
    from skillloop.protocol import canonical_json_line
    if total+len(canonical_json_line(grant))+len(canonical_json_line(job))>maximum_bytes:
        raise ValueError('private_capture_complete_assignment_and_grant_capacity')
    _publish(assignments/'assignment.json',job,21004)
    for parent,_,_ in os.walk(target,topdown=False):
        budget();fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    return job
