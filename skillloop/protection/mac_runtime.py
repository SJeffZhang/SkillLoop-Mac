"""Fresh network-free Mac agent containers; the controller owns Docker access."""
from __future__ import annotations
import dataclasses,io,json,os,re,tarfile,uuid
from pathlib import Path, PurePosixPath
from datetime import datetime,timezone
from skillloop.runtime.docker_api import DockerEngine
from skillloop.protocol import digest_jcs, canonical_json_line

def worker_configuration(*,image,run_volume,socket_volume,model_volume,runtime_uid,tokenizer_mount=None):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise ValueError('immutable_runtime_image_required')
    if (type(runtime_uid) is not int or runtime_uid not in {21002,31003}
            or any(type(v) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',v)
                   for v in (run_volume,socket_volume,model_volume))):
        raise ValueError('runtime_role_or_volume_identity')
    value={'Image':image,'User':str(runtime_uid)+':'+str(runtime_uid),
        'Entrypoint':['python'],'Cmd':['/code/scripts/mac_agent_runtime.py'],
        'Env':['HF_HUB_OFFLINE=1','TRANSFORMERS_OFFLINE=1','PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
            'SecurityOpt':['no-new-privileges'],'PidsLimit':128,'Memory':2*1024**3,'NanoCpus':2*10**9,
            'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=128m'},
            'Mounts':[{'Type':'volume','Source':run_volume,'Target':'/current','ReadOnly':True},
                {'Type':'volume','Source':run_volume,'Target':'/evidence','ReadOnly':False,'VolumeOptions':{'Subpath':'evidence'}},
                {'Type':'volume','Source':socket_volume,'Target':'/socket','ReadOnly':True},
                {'Type':'volume','Source':model_volume,'Target':'/model-bridge','ReadOnly':True}]}}
    if tokenizer_mount is not None:
        if (type(tokenizer_mount) is not dict or set(tokenizer_mount)!={'volume','subpath'}
                or type(tokenizer_mount['volume']) is not str
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',tokenizer_mount['volume'])
                or type(tokenizer_mount['subpath']) is not str):
            raise ValueError('runtime_tokenizer_volume_pin')
        subpath=PurePosixPath(tokenizer_mount['subpath'])
        if (not subpath.parts or subpath.is_absolute() or '..' in subpath.parts
                or str(subpath)!=tokenizer_mount['subpath']):
            raise ValueError('runtime_tokenizer_subpath_pin')
        value['HostConfig']['Mounts'].append({'Type':'volume','Source':tokenizer_mount['volume'],
            'Target':'/model','ReadOnly':True,'VolumeOptions':{'Subpath':tokenizer_mount['subpath']}})
    return value

def container_execute(output,profile,skill,request,binding,config,mutation,attempt,deployment,*,resource_context=None,imported_selection=None,run_lease=None,trust_revision=None):
    resources=resource_context or {'socket_volume':config['mac_socket_volume'],'model_volume':config['mac_model_volume']}
    peer_uid=resources.get('proxy_server_uid',config.get('proxy_service_uid'))
    if type(peer_uid) is not int or peer_uid<0:raise ValueError('trusted_proxy_server_uid_required')
    if run_lease is not None:
        from skillloop.protocol import validate_envelope
        from skillloop.proxy.store import _parse, _now
        validate_envelope(run_lease)
        if (run_lease['kind']!='Lease' or run_lease['body']['run_id']!=binding['body']['run_id']
                or run_lease['body']['state']!='active' or _parse(run_lease['body']['expires_at'])<=_now()
                or type(trust_revision) is not int or trust_revision<1):
            raise ValueError('runtime_actual_lease_binding')
    elif config.get('whole_flow_required'):
        raise ValueError('runtime_actual_lease_required')
    engine=DockerEngine(config.get('docker_engine_socket','/var/run/docker.sock'))
    whole=config.get('whole_flow_required') is True
    if whole and os.geteuid()!=21001:
        raise PermissionError('formal_development_runtime_actual_controller')
    tokenizer_mount=resources.get('tokenizer_mount')
    if whole and tokenizer_mount is None:
        raise ValueError('formal_runtime_tokenizer_mount_required')
    # Validate all mount pins before creating any volume or Keeper.
    worker_configuration(image=config['mac_runtime_image'],run_volume='preflight',
        socket_volume=resources['socket_volume'],model_volume=resources['model_volume'],
        runtime_uid=21002,tokenizer_mount=tokenizer_mount)
    quota=config.get('runtime_evidence_volume_bytes')
    keeper_deadline=None
    if whole:
        if type(quota) is not int or not 4096<=quota<=2147483648:
            raise ValueError('formal_runtime_volume_capacity_required')
        keeper_deadline=datetime.fromisoformat(config['evidence_keeper_deadline'].replace('Z','+00:00'))
        if keeper_deadline.tzinfo is None or not 1<(keeper_deadline-datetime.now(timezone.utc)).total_seconds()<=28800:
            raise ValueError('formal_runtime_keeper_original_deadline')
    volume='skillloop-agent-'+uuid.uuid4().hex
    helper=probe=worker=keeper=None
    def record_lifecycle(state, failures=None):
        # This trusted record locates only resources created by this invocation.
        # A timeout/response loss preserves evidence; it cannot authorize replay.
        record={'kind':'MacRuntimeResourceLifecycle','state':state,
                'run_request_digest':request['digest'],'deployment_epoch':deployment,
                'image':config['mac_runtime_image'],'run_volume':volume,
                'helper_id':helper,'probe_id':probe,'worker_id':worker,
                'keeper_id':keeper,'quota_bytes':quota if whole else None,
                'keeper_deadline':config.get('evidence_keeper_deadline') if whole else None,
                'cleanup_errors':failures or [],'evidence_retained':True}
        record['digest']=digest_jcs(record)
        temporary=output/'runtime-lifecycle.json.tmp'
        with temporary.open('w') as stream:
            json.dump(record,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,0o600)
        os.replace(temporary,output/'runtime-lifecycle.json')
    record_lifecycle('creating_resources')
    try:
        labels={'skillloop.run_request':request['digest'],'skillloop.epoch':deployment,
                'skillloop.role':'runtime-evidence'}
        options={'type':'tmpfs','device':'tmpfs','o':f'size={quota},mode=0700'} if whole else None
        engine.create_volume(volume,driver_options=options,labels=labels if whole else None)
        record_lifecycle('volume_created')
        if whole:
            actual=engine.inspect_volume(volume)
            if actual.get('Name')!=volume or actual.get('Options')!=options or actual.get('Labels')!=labels:
                raise ValueError('formal_runtime_volume_actual_identity')
            seconds=int((keeper_deadline-datetime.now(timezone.utc)).total_seconds())
            keeper=engine.create(volume+'-keeper',{'Image':config['mac_runtime_image'],'User':'21001:21001',
                'Entrypoint':['python'],'Cmd':['-c',f'import time;time.sleep({seconds})'],
                'Labels':labels,'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,
                    'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'PidsLimit':16,
                    'Memory':134217728,'NanoCpus':1000000000,
                    'Mounts':[{'Type':'volume','Source':volume,'Target':'/retained','ReadOnly':True}]}})
            record_lifecycle('keeper_created')
            engine.start(keeper)
            observed=engine.inspect(keeper)
            mounts=observed.get('Mounts',[])
            if (observed.get('Id')!=keeper or observed.get('Image')!=config['mac_runtime_image']
                    or not observed['State']['Running'] or observed['Config']['User']!='21001:21001'
                    or len(mounts)!=1 or mounts[0].get('Name')!=volume or mounts[0].get('RW') is not False):
                raise ValueError('formal_runtime_active_keeper_required')
            record_lifecycle('keeper_active_before_first_write')
        current={'profile':profile,'skill':skill.decode() if imported_selection is None else None,'request':request,'binding':binding,'config':config,
            'mutation':dataclasses.asdict(mutation) if mutation else None,'attempt':attempt,'deployment':deployment,'proxy_server_uid':peer_uid,'run_lease':run_lease,'trust_revision':trust_revision}
        if imported_selection is not None:
            imported_selection.check_binding(binding)
            instruction=next(rid for path,rid,_ in imported_selection.files if path=='SKILL.md')
            current['package_resources']={'instruction':instruction,'references':
                [rid for path,rid,_ in imported_selection.files if path!='SKILL.md']}
        if whole:
            current['kind']='FormalCurrentRuntimeRequest'
            current['digest']=digest_jcs(current)
        # Stage private input through Engine archive API, never a process argument.
        helper=engine.create(volume+'-init',{'Image':config['mac_runtime_image'],'User':'0','Entrypoint':['python'],
            'Cmd':['-c','import os;os.chmod("/stage",0o711);os.makedirs("/stage/evidence");os.chmod("/stage/evidence",0o700);os.chown("/stage/evidence",21002,21002)'],
            'HostConfig':{'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':['CHOWN'],
                'Mounts':[{'Type':'volume','Source':volume,'Target':'/stage'}]}})
        record_lifecycle('initializer_created')
        data=canonical_json_line(current);payload=io.BytesIO()
        with tarfile.open(fileobj=payload,mode='w') as archive:
            info=tarfile.TarInfo('current-request.json');info.size=len(data);info.mode=0o400;info.uid=21002;info.gid=21002
            archive.addfile(info,io.BytesIO(data))
        engine.request('PUT','/containers/'+helper+'/archive?path=/stage',payload.getvalue())
        engine.start(helper);initialized=engine.wait(helper,30)
        if initialized['StatusCode']!=0:raise RuntimeError('runtime_volume_init_failed')
        engine.remove(helper);helper=None
        worker_config=worker_configuration(image=config['mac_runtime_image'],run_volume=volume,
            socket_volume=resources['socket_volume'],model_volume=resources['model_volume'],runtime_uid=21002,
            tokenizer_mount=tokenizer_mount)
        worker_config['Labels']={'skillloop.controller':os.environ.get('SKILLLOOP_CONTROLLER_ID','admission'),'skillloop.run_request':request['digest']}
        worker=engine.create(volume,worker_config)
        if whole:
            from skillloop.runtime.evaluation_dispatch import _verify_role_process
            _verify_role_process(engine.inspect(worker),worker,worker_config,worker_config['HostConfig']['Mounts'])
        record_lifecycle('runtime_created')
        # Probe the live sockets before permitting the actual model worker.
        probe_code = """import json,socket
checks={}
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(2);s.connect('/socket/tool.sock');s.sendall(b'{}\\n');checks['foreign_peer_uid']=json.loads(s.recv(4096))['error_code'];s.close()
try:open('/current/current-request.json').read();checks['foreign_input']='unexpected_access'
except PermissionError:checks['foreign_input']='denied'
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
try:s.connect(('1.1.1.1',443));checks['external_network']='unexpected_access'
except OSError:checks['external_network']='denied'
print(json.dumps(checks))
"""
        probe_config=worker_configuration(image=config['mac_runtime_image'],run_volume=volume,
            socket_volume=resources['socket_volume'],model_volume=resources['model_volume'],runtime_uid=31003)
        probe_config['Cmd']=['-c',probe_code]
        probe_config['HostConfig']['Mounts']=[m for m in probe_config['HostConfig']['Mounts'] if m['Target']!='/evidence']
        probe=engine.create(volume+'-boundary-probe',probe_config)
        record_lifecycle('boundary_probe_created')
        engine.start(probe)
        probe_state=engine.wait(probe,15)
        if probe_state['StatusCode']!=0:raise RuntimeError('boundary_probe_execution_failed')
        checks=json.loads(engine.logs(probe));(output/'boundary-probe.json').write_text(json.dumps(checks,indent=2))
        if set(checks.values())!={'denied'}:raise RuntimeError('boundary_probe_failed')
        engine.remove(probe);probe=None
        if whole:
            # Volume initialization and the live boundary probe happen after
            # Lease issuance. Do not borrow their elapsed time from the model
            # run or launch a worker that can no longer fit its actual Lease.
            left=(_parse(run_lease['body']['expires_at'])-_now()).total_seconds()
            if left<=config['worker_deadline_seconds']:
                record_lifecycle('startup_exhausted_actual_lease_before_runtime')
                raise TimeoutError('formal_runtime_startup_exhausted_actual_lease')
            if (keeper_deadline-datetime.now(timezone.utc)).total_seconds()<=config['worker_deadline_seconds']+120:
                record_lifecycle('startup_exhausted_original_terminal_reserve')
                raise TimeoutError('formal_runtime_startup_exhausted_original_clock')
        engine.start(worker)
        try:
            state=engine.wait(worker,config.get('worker_deadline_seconds',265))
            inspect=engine.inspect(worker)
            if whole:
                _verify_role_process(inspect,worker,worker_config,worker_config['HostConfig']['Mounts'])
            metadata={'container_id':worker,'run_volume':volume,'image':inspect['Image'],
                'network_mode':inspect['HostConfig']['NetworkMode'],'state':state,'exported':False}
            (output/'container-execution.json').write_text(json.dumps(metadata,indent=2))
            if whole:
                raw_logs=engine.logs(worker,maximum_bytes=1048576,timeout=5)
                fd=os.open(output/'runtime-process.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(raw_logs);stream.flush();os.fsync(stream.fileno())
            if state['StatusCode']!=0:raise RuntimeError('isolated_runtime_failed')
            evidence=output/'evidence';evidence.mkdir(mode=0o700)
            maximum_bytes=config.get('maximum_runtime_evidence_bytes')
            maximum_files=config.get('maximum_runtime_evidence_files')
            if whole and (type(maximum_bytes) is not int or maximum_bytes<1 or
                          type(maximum_files) is not int or maximum_files<1):
                raise ValueError('runtime_frozen_evidence_capacity_required')
            archive_limit=maximum_bytes+maximum_files*2048+10240 if whole else None
            seen=set();exported_bytes=0
            with tarfile.open(fileobj=io.BytesIO(engine.archive(worker,'/evidence',maximum_bytes=archive_limit)),mode='r:*') as archive:
                for member in archive:
                    relative=Path(member.name)
                    if not relative.parts or relative.parts[0]!='evidence' or relative.is_absolute() or '..' in relative.parts or member.issym() or member.islnk() or member.name in seen:raise ValueError('unsafe_evidence_archive')
                    seen.add(member.name)
                    if whole and len(seen)>maximum_files:raise ValueError('runtime_evidence_file_capacity')
                    destination=evidence.joinpath(*relative.parts[1:])
                    if member.isdir():destination.mkdir(parents=True,exist_ok=True,mode=0o700)
                    elif member.isfile():
                        exported_bytes+=member.size
                        if whole and exported_bytes>maximum_bytes:raise ValueError('runtime_evidence_byte_capacity')
                        destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                        with archive.extractfile(member) as source,destination.open('xb') as target:
                            remaining=member.size
                            while remaining:
                                block=source.read(min(1048576,remaining))
                                if not block:raise ValueError('runtime_evidence_truncated')
                                target.write(block);remaining-=len(block)
                            target.flush();os.fsync(target.fileno())
                        os.chmod(destination,0o600)
                    else:raise ValueError('unsafe_evidence_archive')
            result=json.loads((evidence/'adapter-result.json').read_text())
            result['trace_path']=str(evidence/Path(result['trace_path']).name)
            metadata['exported']=True
            (output/'container-execution.json').write_text(json.dumps(metadata,indent=2))
            # Keep the stopped container and volume until the controller has reduced
            # evidence and made a consistent authority backup. Cleanup is explicit.
            record_lifecycle('exported_awaiting_independent_review')
            return result
        except BaseException:
            # Outer custody handler preserves the primary exception even if
            # inspection/stop fails while attempting to retain owned evidence.
            raise
    except BaseException:
        failures=[]
        for role,identifier in (('helper',helper),('boundary_probe',probe),('runtime',worker)):
            if identifier is None:continue
            try:
                actual=engine.inspect(identifier)
                if actual['Id']!=identifier:raise ValueError('runtime_resource_identity')
                if actual['State']['Running']:
                    engine.request('POST','/containers/'+identifier+'/stop?t=1')
            except BaseException as failure:
                failures.append({'role':role,'container_id':identifier,'error_type':type(failure).__name__})
        # Preserve named volume and stopped containers, including incomplete init.
        # Administrative recovery requires exact IDs and exported evidence review.
        try:record_lifecycle('failed_evidence_retained',failures)
        except BaseException:pass  # Never mask the original execution uncertainty.
        raise
