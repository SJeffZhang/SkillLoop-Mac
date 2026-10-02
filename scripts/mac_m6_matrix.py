"""Resume a frozen Mac matrix without repeating a consumed execution slot."""
import argparse,json,os,subprocess,time,urllib.request
from pathlib import Path
from scripts.mac_m6_gate import gate,load,sealed,result_path
from skillloop.protocol import digest_jcs
from skillloop.repair.budget import SpendingLedger


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix('.tmp')
    with temporary.open('w') as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(temporary,path)

def model_identity(config):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open('http://127.0.0.1:11434/api/ps',timeout=2) as response:app_models=json.load(response).get('models',[])
    except OSError:app_models=[]
    if app_models:raise ValueError('another_ollama_service_has_loaded_models')
    for route,key,expected in [('version','version',config['ollama_version']),('tags',None,None)]:
        with opener.open(f"http://127.0.0.1:{config['model_service_port']}/api/{route}",timeout=10) as response:data=json.load(response)
        if key and data[key]!=expected:raise ValueError('ollama_version_changed')
        if route=='tags' and not any(model['name']==config['model_id'] and 'sha256:'+model['digest']==config['model_manifest_digest'] for model in data['models']):raise ValueError('model_snapshot_changed')

def validated_entry_path(root, entry, entry_path=None):
    path = Path(entry_path) if entry_path is not None else root/'entries'/entry['profile']/(entry['entry_id']+'.json')
    if not path.is_file():
        raise ValueError('entry_bind_source_not_file')
    if sealed(load(path)) != entry:
        raise ValueError('entry_bind_identity_mismatch')
    return path.resolve()

def execute(root,archive,entry,ledger,entry_path=None,resource_admission=None):
    target=result_path(root,entry).parent
    if (target/'result.json').exists():
        if resource_admission is not None:resource_admission.release(entry)
        return 'retained_completed'
    name='skillloop-m6-'+entry['digest'][7:27];prefix=name
    spent=any(e['item_key']==entry['entry_id'] and e['attempt']==0 for e in ledger.read()['executions'])
    if not spent:
        bound_entry = validated_entry_path(root, entry, entry_path)
        model_identity(entry['config'])
        if resource_admission is not None:resource_admission.reserve(entry)
        try:ledger.consume(entry['entry_id'],0)
        except BaseException:
            # The worker has not been launched. Spending is never rolled back,
            # even if the durable ledger write completed before raising.
            if resource_admission is not None:resource_admission.release(entry)
            raise
        subject=Path(entry['subject_root']) if entry.get('kind')=='protected' else ((archive/manifest_campaign(root,entry)/'candidate') if entry['role']=='candidate' else root/'submitted'/entry['profile'])
        command=['docker','run','--name',name,'--network','host','-v','/var/run/docker.sock:/var/run/docker.sock',
            '-v',prefix+'-authority:/work','-v',prefix+'-model:/bridge','-v',prefix+'-proxy:/interfaces',
            '--mount','type=bind,src='+str(bound_entry)+',dst=/entry.json,readonly',
            '-v',str(subject.resolve())+':/subject:ro','-e','SKILLLOOP_CONTROLLER_ID='+name,entry['config']['mac_runtime_image'],'scripts/mac_container_admission.py',
            '--image',entry['config']['mac_runtime_image'],'--socket-volume',prefix+'-proxy','--model-volume',prefix+'-model',
            '--model-port',str(entry['config']['model_service_port']),'--run-entry','/entry.json']
        log=root/'logs'/(entry['entry_id']+'.log');log.parent.mkdir(exist_ok=True)
        try:
            with log.open('wb') as stream:proc=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,timeout=entry['config']['worker_deadline_seconds'])
        except subprocess.TimeoutExpired:
            owned=subprocess.run(['docker','ps','--filter','label=skillloop.controller='+name,'--format','{{.ID}}'],capture_output=True,text=True,check=True)
            for worker in owned.stdout.splitlines():subprocess.run(['docker','stop','-t','1',worker],capture_output=True)
            subprocess.run(['docker','stop','-t','1',name],capture_output=True)
            return 'controller_deadline_exceeded'
        if proc.returncode:return 'controller_failed'
    else:
        inspected=subprocess.run(['docker','inspect',name],capture_output=True,text=True)
        if inspected.returncode:return 'consumed_without_container'
        state=json.loads(inspected.stdout)[0]['State']
        if state['Running']:
            subprocess.run(['docker','wait',name],capture_output=True,check=True)
            state=json.loads(subprocess.check_output(['docker','inspect',name]))[0]['State']
        if state['ExitCode']!=0:return 'retained_failed_controller'
    source='/work/'+entry['case_id']+'.'+entry['role']+'.'+str(entry['repetition'])
    target.parent.mkdir(parents=True,exist_ok=True)
    copied=subprocess.run(['docker','cp',name+':'+source,str(target)],capture_output=True,text=True)
    exported=copied.returncode==0 and (target/'result.json').exists()
    if exported and resource_admission is not None:resource_admission.release(entry)
    return 'exported' if exported else 'export_failed'

def manifest_campaign(root,entry):return load(root/'manifest.json')['profiles'][entry['profile']]['inherited_campaign']

def resource_admission_from_args(args,manifest):
    values=(args.resource_admission_plan,args.resource_admission_state,args.resource_admission_socket)
    if not any(values):return None
    if not all(values):raise ValueError('resource_admission_arguments')
    plan=sealed(load(args.resource_admission_plan))
    if (plan['manifest_digest']!=manifest['digest'] or
        plan['config_id']!=manifest['config'].get('resource_admission_config')):
        raise ValueError('resource_admission_manifest')
    from skillloop.runtime.controller_reservation import ControllerResourceAdmission
    return ControllerResourceAdmission(plan,args.resource_admission_state,args.resource_admission_socket)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--archive',type=Path,required=True);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--tokenizer',type=Path,required=True)
    parser.add_argument('--resource-admission-plan',type=Path);parser.add_argument('--resource-admission-state',type=Path);parser.add_argument('--resource-admission-socket',type=Path);args=parser.parse_args()
    os.umask(0o077);root=args.root.resolve();manifest=sealed(load(root/'manifest.json'));entries=[sealed(load(root/p)) for p in manifest['entries']]
    admission=resource_admission_from_args(args,manifest)
    model_identity(manifest['config']);status=load(root/'status.json') if (root/'status.json').exists() else {'kind':'MacM6MatrixStatus','manifest_digest':manifest['digest'],'entries':{},'phase':'capacity'}
    if status['manifest_digest']!=manifest['digest']:raise ValueError('resume_manifest_changed')
    for profile in manifest['profiles']:
        clock=root/'spending'/ (profile+'-clock.json')
        if not clock.exists():
            clock_value={'started_at':time.time(),'manifest_digest':manifest['digest']};save(clock,{**clock_value,'digest':digest_jcs(clock_value)})
        value=load(clock)
        if value['manifest_digest']!=manifest['digest']:raise ValueError('resume_clock_binding')
        ledger=SpendingLedger(root/'spending'/(profile+'.json'),victim_seconds=manifest['config']['worker_deadline_seconds'],campaign_started_at=value['started_at'])
        current=[e for e in entries if e['profile']==profile]
        for entry in [e for e in current if e['kind']=='capacity']:
            outcome=execute(root,args.archive,entry,ledger,resource_admission=admission);status['entries'][entry['entry_id']]=outcome;save(root/'status.json',status);print(profile,entry['entry_id'],outcome,flush=True)
        calibration=gate(root,args.archive,args.source,args.tokenizer,calibration_only=True);save(root/'calibration-gate.json',calibration)
        if calibration['profiles'][profile]['verdict']!='calibration_ready':
            status.update(phase='capacity_blocked',profile=profile);save(root/'status.json',status);return
        status.update(phase='formal_M6',profile=profile);save(root/'status.json',status)
        for entry in [e for e in current if e['kind']=='formal']:
            outcome=execute(root,args.archive,entry,ledger,resource_admission=admission);status['entries'][entry['entry_id']]=outcome;save(root/'status.json',status);print(profile,entry['entry_id'],outcome,flush=True)
            if outcome in {'controller_failed','controller_deadline_exceeded','export_failed','consumed_without_container','retained_failed_controller'}:
                status.update(phase='infrastructure_attention');save(root/'status.json',status);return
        report=gate(root,args.archive,args.source,args.tokenizer);save(root/'m6-gate.json',report)
        status['profile_gates']= {p:v['verdict'] for p,v in report['profiles'].items()};save(root/'status.json',status)
    status.update(phase='M6_matrix_complete');save(root/'status.json',status)

if __name__=='__main__':main()
