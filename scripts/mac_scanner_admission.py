"""Trusted Linux controller: original scanner OCI, zero network, VM UDS relay."""
import argparse,io,json,os,tarfile,time,uuid
from pathlib import Path
from deploy.scanner.qwen_relay import HostModelBridge
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.discovery.scanner import reduce_scan
from skillloop.families.fixtures import load_example_skill
from skillloop.families.registry import FAMILY_SPEC
from skillloop.protocol import digest_bytes

SCANNER='sha256:165f1d7ae6e878970136b78bda4fb9b7cc5a52d305734f7d3b6318d6434ffe9c'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--controller-image',required=True);parser.add_argument('--model-volume',required=True);parser.add_argument('--profile',required=True);parser.add_argument('--skill-file',type=Path);args=parser.parse_args()
    os.umask(0o077);engine=DockerEngine();prefix='skillloop-scan-'+uuid.uuid4().hex
    source_volume=prefix+'-input';report_volume=prefix+'-report'
    engine.create_volume(source_volume);engine.create_volume(report_volume)
    skill=args.skill_file.read_bytes() if args.skill_file else load_example_skill(args.profile,root=FAMILY_SPEC/'redteam')
    helper=engine.create(prefix+'-init',{'Image':args.controller_image,'Entrypoint':['python'],
        'Cmd':['-c','import os;os.chmod("/report",0o700);os.chown("/report",21003,21003)'],
        'HostConfig':{'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':['CHOWN'],'Mounts':[
            {'Type':'volume','Source':source_volume,'Target':'/stage'},
            {'Type':'volume','Source':report_volume,'Target':'/report'}]}})
    guest=Path('/code/deploy/scanner/qwen_scan_guest.py').read_text().replace('Qwen/Qwen3.8-27B-FP8','qwen3.8:27b-mxfp8')
    files={'SKILL.md':skill,'qwen_scan_guest.py':guest.encode(),'qwen_relay.py':Path('/code/deploy/scanner/qwen_relay.py').read_bytes(),
        'qwen-model-registry.yaml':b'models:\n  "qwen3.8:27b-mxfp8":\n    context_length: 16384\n    max_output_tokens: 2048\n'}
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w') as archive:
        for name,data in files.items():
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o400;info.uid=21003;info.gid=21003
            archive.addfile(info,io.BytesIO(data))
    engine.request('PUT','/containers/'+helper+'/archive?path=/stage',buffer.getvalue());engine.start(helper)
    if engine.wait(helper,30)['StatusCode']!=0:raise ValueError('scanner_volume_init_failed')
    engine.remove(helper)
    output=Path('/work')/args.profile;output.mkdir(mode=0o700,exist_ok=False)
    class AuditTokenizer:
        def __init__(self):
            self.tokenizer=ExactLocalTokenizer('/model');self.index=0
        def count(self,messages,tools,**kwargs):
            self.index+=1
            (output/('model-input-'+str(self.index)+'.json')).write_text(json.dumps({'messages':messages,'tools':tools},ensure_ascii=False))
            return self.tokenizer.count(messages,tools,**kwargs)
    started=time.monotonic()
    with HostModelBridge(Path('/bridge/qwen.sock'),model_port=11434,model_id='qwen3.8:27b-mxfp8',backend='ollama',max_chat_requests=4,tokenizer=AuditTokenizer()) as bridge:
        os.chown('/bridge/qwen.sock',21003,21003)
        scanner=engine.create(prefix,{'Image':SCANNER,'User':'21003:21003','Entrypoint':['python'],'Cmd':['/scan-config/qwen_scan_guest.py'],
            'Env':['HOME=/tmp','XDG_CACHE_HOME=/tmp/cache','LANGCHAIN_TRACING_V2=false','HTTP_PROXY=','HTTPS_PROXY=','ALL_PROXY=',
                'NO_PROXY=127.0.0.1,localhost','SKILLSPECTOR_PROVIDER=openai','SKILLSPECTOR_MAX_LLM_CONCURRENCY=1',
                'SKILLSPECTOR_MAX_WORKFLOW_SECONDS=300','SKILLSPECTOR_MODEL=qwen3.8:27b-mxfp8',
                'SKILLSPECTOR_MODEL_REGISTRY=/scan-config/qwen-model-registry.yaml','OPENAI_BASE_URL=http://127.0.0.1:31000/v1','OPENAI_API_KEY=local-scanner-only'],
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                'PidsLimit':256,'Memory':2*1024**3,'NanoCpus':2*10**9,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=256m'},
                'Mounts':[{'Type':'volume','Source':source_volume,'Target':target,'ReadOnly':True} for target in ('/subject','/scan-config')]+[
                    {'Type':'volume','Source':'skillloop-mac-offline-osv','Target':'/osv-data','ReadOnly':True},
                    {'Type':'volume','Source':args.model_volume,'Target':'/model-bridge','ReadOnly':True},
                    {'Type':'volume','Source':report_volume,'Target':'/report'}]}})
        engine.start(scanner)
        try:exit_code=engine.wait(scanner,300)['StatusCode']
        except OSError:
            engine.request('POST','/containers/'+scanner+'/stop?t=1');exit_code=124
        (output/'scanner.log').write_bytes(engine.logs(scanner))
        with tarfile.open(fileobj=io.BytesIO(engine.archive(scanner,'/report'))) as archive:
            for member in archive.getmembers():
                path=Path(member.name)
                if path.parts[0]!='report' or '..' in path.parts or path.is_absolute() or member.issym() or member.islnk():raise ValueError('unsafe_scanner_archive')
                target=output.joinpath(*path.parts[1:])
                if member.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o700)
                elif member.isfile():target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(archive.extractfile(member).read())
                else:raise ValueError('unsafe_scanner_archive')
        result={'scope':'scanner_admission_not_formal_M6','exit_code':exit_code,'elapsed_seconds':time.monotonic()-started,
            'container_id':scanner,'scanner_image':SCANNER,'qwen_calls':bridge.chat_requests,'model_usage':bridge.usage_records,'subject_digest':digest_bytes(skill)}
    if (output/'report.json').exists():
        report,findings,dispositions=reduce_scan(args.profile,(output/'report.json').read_bytes(),exit_code,subject_digest=digest_bytes(skill),require_llm=True,allow_risk_exit=True)
        result.update(scanner_report=report,findings=findings,dispositions=dispositions)
    else:result['status']='incomplete_raw_report_missing'
    (output/'invocation.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({'profile':args.profile,'exit_code':exit_code,'qwen_calls':result['qwen_calls'],'raw_report':(output/'report.json').exists()}),flush=True)

if __name__=='__main__':main()
