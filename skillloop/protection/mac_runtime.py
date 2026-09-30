"""Fresh network-free Mac agent containers; the controller owns Docker access."""
from __future__ import annotations
import dataclasses,io,json,os,re,tarfile,uuid
from pathlib import Path
from skillloop.runtime.docker_api import DockerEngine

def worker_configuration(*,image,run_volume,socket_volume,model_volume,runtime_uid):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise ValueError('immutable_runtime_image_required')
    return {'Image':image,'User':str(runtime_uid)+':'+str(runtime_uid),
        'Entrypoint':['python'],'Cmd':['/code/scripts/mac_agent_runtime.py'],
        'Env':['HF_HUB_OFFLINE=1','TRANSFORMERS_OFFLINE=1','PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
            'SecurityOpt':['no-new-privileges'],'PidsLimit':128,'Memory':2*1024**3,'NanoCpus':2*10**9,
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=128m'},
            'Mounts':[{'Type':'volume','Source':run_volume,'Target':'/current','ReadOnly':True},
                {'Type':'volume','Source':run_volume,'Target':'/evidence','ReadOnly':False,'VolumeOptions':{'Subpath':'evidence'}},
                {'Type':'volume','Source':socket_volume,'Target':'/socket','ReadOnly':True},
                {'Type':'volume','Source':model_volume,'Target':'/model-bridge','ReadOnly':True}]}}

def container_execute(output,profile,skill,request,binding,config,mutation,attempt,deployment,*,resource_context=None):
    resources=resource_context or {'socket_volume':config['mac_socket_volume'],'model_volume':config['mac_model_volume']}
    engine=DockerEngine(config.get('docker_engine_socket','/var/run/docker.sock'))
    volume='skillloop-agent-'+uuid.uuid4().hex
    engine.create_volume(volume)
    current={'profile':profile,'skill':skill.decode(),'request':request,'binding':binding,'config':config,
        'mutation':dataclasses.asdict(mutation) if mutation else None,'attempt':attempt,'deployment':deployment}
    # Stage private input through Engine archive API, never a process argument.
    helper=engine.create(volume+'-init',{'Image':config['mac_runtime_image'],'User':'0','Entrypoint':['python'],
        'Cmd':['-c','import os;os.makedirs("/stage/evidence");os.chmod("/stage/evidence",0o700);os.chown("/stage/evidence",21002,21002)'],
        'HostConfig':{'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':['CHOWN'],
            'Mounts':[{'Type':'volume','Source':volume,'Target':'/stage'}]}})
    data=json.dumps(current,ensure_ascii=False).encode();payload=io.BytesIO()
    with tarfile.open(fileobj=payload,mode='w') as archive:
        info=tarfile.TarInfo('current-request.json');info.size=len(data);info.mode=0o400;info.uid=21002;info.gid=21002
        archive.addfile(info,io.BytesIO(data))
    engine.request('PUT','/containers/'+helper+'/archive?path=/stage',payload.getvalue())
    engine.start(helper);initialized=engine.wait(helper,30)
    if initialized['StatusCode']!=0:raise RuntimeError('runtime_volume_init_failed')
    engine.remove(helper)
    worker=engine.create(volume,worker_configuration(image=config['mac_runtime_image'],run_volume=volume,
        socket_volume=resources['socket_volume'],model_volume=resources['model_volume'],runtime_uid=21002))
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
    probe=engine.create(volume+'-boundary-probe',probe_config);engine.start(probe)
    probe_state=engine.wait(probe,15)
    if probe_state['StatusCode']!=0:raise RuntimeError('boundary_probe_execution_failed')
    checks=json.loads(engine.logs(probe));(output/'boundary-probe.json').write_text(json.dumps(checks,indent=2))
    if set(checks.values())!={'denied'}:raise RuntimeError('boundary_probe_failed')
    engine.remove(probe)
    engine.start(worker)
    try:
        state=engine.wait(worker,config.get('worker_deadline_seconds',265))
        inspect=engine.inspect(worker)
        metadata={'container_id':worker,'run_volume':volume,'image':inspect['Image'],
            'network_mode':inspect['HostConfig']['NetworkMode'],'state':state,'exported':False}
        (output/'container-execution.json').write_text(json.dumps(metadata,indent=2))
        if state['StatusCode']!=0:raise RuntimeError('isolated_runtime_failed')
        evidence=output/'evidence';evidence.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(engine.archive(worker,'/evidence')),mode='r:*') as archive:
            for member in archive.getmembers():
                relative=Path(member.name)
                if relative.parts[0]!='evidence' or relative.is_absolute() or '..' in relative.parts or member.issym() or member.islnk():raise ValueError('unsafe_evidence_archive')
                destination=evidence.joinpath(*relative.parts[1:])
                if member.isdir():destination.mkdir(parents=True,exist_ok=True,mode=0o700)
                elif member.isfile():
                    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    with destination.open('xb') as target:target.write(archive.extractfile(member).read())
                    os.chmod(destination,0o600)
                else:raise ValueError('unsafe_evidence_archive')
        result=json.loads((evidence/'adapter-result.json').read_text())
        result['trace_path']=str(evidence/Path(result['trace_path']).name)
        metadata['exported']=True
        (output/'container-execution.json').write_text(json.dumps(metadata,indent=2))
        # Keep the stopped container and volume until the controller has reduced
        # evidence and made a consistent authority backup. Cleanup is explicit.
        return result
    except BaseException:
        if engine.inspect(worker)['State']['Running']:
            engine.request('POST','/containers/'+worker+'/stop?t=1')
        raise
