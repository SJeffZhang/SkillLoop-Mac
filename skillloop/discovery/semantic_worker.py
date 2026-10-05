"""Gateway-owned pinned SkillSpector semantic pass; Scanner gains no model RPC."""
from datetime import datetime,timezone
import base64,hashlib,os,subprocess,sys
from pathlib import Path
from deploy.scanner.qwen_relay import HostModelBridge,run_guest_relay
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.discovery.scanner import reduce_scan
from skillloop.protocol import digest_bytes,digest_jcs
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.model_bridge_service import backend_identity
from skillloop.runtime.round_manifest import read_round_manifest


def main():
    os.umask(0o077)
    if os.geteuid()!=21011 or 21001 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('semantic_actual_model_gateway')
    job=read_owned('/assignment/job.json',uid=21001,gid=21011,limit=2097152)
    fields={'kind','campaign_digest','profile','source_snapshot','skill_b64','model_policy','scanner_files',
            'whole_round_manifest_digest','worker_seconds','digest'}
    if set(job)!=fields or job['kind']!='FormalGatewaySemanticDiscovery':raise ValueError('semantic_frozen_assignment')
    whole=read_round_manifest('/whole-round/manifest.json');policy=job['model_policy']
    if (whole['digest']!=job['whole_round_manifest_digest'] or policy['whole_round_manifest_digest']!=whole['digest']
            or policy['source_digest']!=whole['source_digest'] or policy['allowed_client_uid']!=21011
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or type(policy['max_chat_requests']) is not int or not 1<=policy['max_chat_requests']<=128
            or type(policy['request_timeout_seconds']) is not int or not 1<=policy['request_timeout_seconds']<=180
            or type(job['worker_seconds']) is not int or not 1<=job['worker_seconds']<=1200
            or policy['max_chat_requests']*policy['request_timeout_seconds']+60>job['worker_seconds']):
        raise ValueError('semantic_complete_original_model_budget')
    from scripts.dgx_m6_repair import source_index
    if digest_jcs(source_index(Path(__file__).resolve().parents[2]))!=whole['source_digest']:
        raise ValueError('semantic_actual_production_source_changed')
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==job['campaign_digest']),None)
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if scope is None or scope['profile']!=job['profile'] or (deadline-datetime.now(timezone.utc)).total_seconds()<=job['worker_seconds']+120:
        raise ValueError('semantic_original_campaign_scope')
    skill=base64.b64decode(job['skill_b64'],validate=True);snapshot=job['source_snapshot']
    from skillloop.protocol import validate_envelope
    validate_envelope(snapshot)
    selected=[f for f in snapshot['body']['files'] if f['path']=='SKILL.md']
    if snapshot['kind']!='SourceSnapshot' or len(selected)!=1 or digest_bytes(skill)!=selected[0]['bytes_digest'] or len(skill)>4096:
        raise ValueError('semantic_actual_source_instruction')
    if type(job['scanner_files']) is not dict or not job['scanner_files'] or len(job['scanner_files'])>1024:
        raise ValueError('semantic_pinned_scanner_implementation')
    for path,pin in job['scanner_files'].items():
        if not path.startswith(('/opt/skillloop-scanner/','/usr/local/lib/python')):
            raise ValueError('semantic_scanner_pin_path')
        target=Path(path)
        if target.is_symlink() or not target.is_file() or digest_bytes(target.read_bytes())!=pin:
            raise ValueError('semantic_scanner_implementation_changed')
    if '/opt/skillloop-scanner/offline_osv.py' not in job['scanner_files']:
        raise ValueError('semantic_actual_scanner_entry_pin')
    evidence=_directory('/report',21011,21001,0o750)
    if any(evidence.iterdir()):raise RuntimeError('semantic_original_attempt_no_reexecution')
    _publish(evidence/'assignment.json',job,21001)
    subject=_directory('/subject',21011,21011,0o700)
    fd=os.open(subject/'SKILL.md',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(skill);stream.flush();os.fsync(stream.fileno())
    tokenizer=ExactLocalTokenizer('/model',expected_hashes=policy['tokenizer_hashes'])
    requests=[]
    responded=set()
    def observe(kind,request,response,status):
        key=digest_bytes(request)
        if kind=='request':
            if requests and len(requests)-1 not in responded:
                raise RuntimeError('semantic_previous_inference_unknown_no_retry')
            slot=len(requests);requests.append(key)
            value={'kind':'SemanticModelRequest','scope_digest':job['digest'],'slot':slot,
                'raw_b64':base64.b64encode(request).decode(),'spent':True,'automatic_replay_allowed':False}
        else:
            if not requests or requests[-1]!=key:raise ValueError('semantic_original_response_identity')
            slot=len(requests)-1
            from skillloop.protocol import decode_json
            try:parsed=decode_json(response)
            except (ValueError,UnicodeError):parsed=None
            if (kind=='response' and status==200 and type(parsed) is dict
                    and parsed.get('done') is True and parsed.get('done_reason')=='stop'):
                responded.add(slot)
            value={'kind':'SemanticModelResponse','scope_digest':job['digest'],'slot':slot,
                'request_digest':key,'http_status':status,'raw_b64':base64.b64encode(response).decode(),
                'body_read_complete':kind=='response'}
        value['digest']=digest_jcs(value);_publish(evidence/(kind+'-'+str(slot)+'.json'),value,21001)
    try:
        identity=backend_identity(policy)
        with HostModelBridge(Path('/model-bridge/model.sock'),model_host=policy['model_host'],model_port=policy['model_port'],
                model_id=policy['model_id'],backend='ollama',native_chat=True,tokenizer=tokenizer,
                allowed_client_uid=21011,max_chat_requests=policy['max_chat_requests'],temperature=policy['temperature'],
                top_p=policy['top_p'],max_output_tokens=policy['max_output_tokens'],
                request_timeout_seconds=policy['request_timeout_seconds'],campaign_deadline=policy['campaign_deadline'],
                semantic_scope_digest=job['digest'],evidence_observer=observe) as bridge:
            server,thread=run_guest_relay(Path('/model-bridge/model.sock'))
            try:
                env={'PATH':'/usr/local/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1',
                    'SKILLSPECTOR_PROVIDER':'openai','SKILLSPECTOR_MODEL':policy['model_id'],
                    'OPENAI_BASE_URL':'http://127.0.0.1:31000/v1','OPENAI_API_KEY':'local-semantic',
                    'OPENAI_MAX_RETRIES':'0'}
                process=subprocess.run([sys.executable,'/opt/skillloop-scanner/offline_osv.py','scan',
                    '/subject/SKILL.md','--format','json','--output','/report/raw-report.json'],env=env,
                    timeout=job['worker_seconds'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
            finally:server.shutdown();server.server_close();thread.join(timeout=5)
            raw_path=evidence/'raw-report.json'
            fd=os.open(raw_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            import stat
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=21011 or info.st_nlink!=1 or info.st_size>33554432:
                    raise ValueError('semantic_raw_report_custody')
                os.fchown(stream.fileno(),-1,21001);os.fchmod(stream.fileno(),0o640)
                raw=stream.read(33554433);os.fsync(stream.fileno())
            if len(responded)!=len(requests) or not requests:raise ValueError('semantic_original_model_attempts_incomplete')
            if len(raw)>33554432:raise ValueError('semantic_raw_report_capacity')
            report,findings,dispositions=reduce_scan(job['profile'],raw,process.returncode,
                subject_digest=snapshot['body']['skill_digest'],require_llm=True,allow_risk_exit=True)
            value={'kind':'GatewaySemanticDiscoveryEvidence','assignment_digest':job['digest'],
                'source_snapshot_digest':snapshot['digest'],'scanner_report':report,'findings':findings,
                'dispositions':dispositions,'backend_identity':identity,'model_requests':bridge.chat_requests,
                'usage_records':bridge.usage_records,'qualification_issued':False}
            value['digest']=digest_jcs(value);_publish(evidence/'discovery.json',value,21001)
    except BaseException:
        failure={'kind':'SemanticDiscoveryUnavailable','assignment_digest':job['digest'],
            'model_attempts':len(requests),'complete_responses':len(responded),
            'automatic_replay_allowed':False,'qualification_issued':False}
        failure['digest']=digest_jcs(failure)
        _publish(evidence/'failure.json',failure,21001)
        raise
    finally:tokenizer.close()


if __name__=='__main__':main()
