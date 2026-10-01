"""Freeze inherited cases, new Mac identities and paired M6 run entries."""
import argparse,base64,copy,json,os,shutil
from pathlib import Path
from scripts.dgx_m6_calibrate import probe_suite
from scripts.dgx_m6_repair import CONFIG,execution_plan,source_index
from skillloop.protocol import digest_bytes,digest_jcs
from skillloop.repair.mac_inheritance import verify_inherited_candidate
from skillloop.runtime.mac_entry import verify_formal_entry

PROFILES={'orders_total':('m6-n11o','orders',42),'refunds_total':('m6-n11r','refunds',66),'markdown_index':('m6-b08','markdown',48)}

def write_sealed(path,value):
    result={**value,'digest':digest_jcs(value)};path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as file:json.dump(result,file,indent=2);file.flush();os.fsync(file.fileno())
    path.chmod(0o400);return result

def stage_submitted(source,target,skill_id,parent_bytes):
    shutil.copytree(source,target)
    if (target/'skills'/skill_id/'SKILL.md').read_bytes()!=parent_bytes:
        raise ValueError('immutable_submitted_snapshot_changed')


def prepare(root,archive,source,scanner_root,tokenizer,image,port,*,
            profiles=None,campaign_prefix='mac-m6-formal-v1',
            config_id='mac-m6-ollama-qwen38-mxfp8-formal-v1',
            deployment_epoch='mac-m6-development-1'):
    selected=tuple(PROFILES) if profiles is None else tuple(profiles)
    if not selected or len(set(selected))!=len(selected) or any(p not in PROFILES for p in selected):
        raise ValueError('supplemental_profile_selection')
    if root.exists():raise ValueError('campaign_already_exists')
    root.mkdir(mode=0o700);index=source_index(source);profile_path=source/'specs/mac/runtime-profile.json'
    config={**CONFIG,'config_id':config_id,'gateway_backend':'ollama','model_id':'qwen3.8:27b-mxfp8',
        'deployment_epoch':deployment_epoch,'backend_template_overhead_tokens':0,'ollama_template_overhead_tokens':0,'tokenizer_path':'/model',
        'mac_runtime_image':image,'model_service_port':port,'ollama_version':'0.33.3','model_manifest_digest':'sha256:464021588235c36e23bd48a480c6c306ed1fc1e0619e97998267494a1be68de4'}
    manifest={'kind':'MacM6FrozenCampaign','config':config,'source_index':index,'runtime_profile_digest':digest_bytes(profile_path.read_bytes()),
        'tokenizer_hashes':{p.name:digest_bytes(p.read_bytes()) for p in tokenizer.iterdir() if p.is_file()},'profiles':{},'entries':[],'formal_required_runs':sum(PROFILES[p][2] for p in selected)}
    for profile in selected:
        campaign,short,required=PROFILES[profile]
        inherited=verify_inherited_candidate(archive/campaign,profile);compiled=json.loads((archive/campaign/profile/'compiled.json').read_text());campaign_id=campaign_prefix+'-'+profile
        parent_text=json.loads((archive/campaign/profile/'file-set.json').read_text())['files']['SKILL.md']
        stage_submitted(source/'specs/v2.2/families/redteam',root/'submitted'/profile,profile.replace('_','-'),parent_text.encode())
        plan=execution_plan(compiled,campaign=campaign_id,submitted_digest=inherited['submitted_subject_digest'],runtime_config=config,runtime_profile_path=profile_path)
        if len(plan['body']['items'])!=required:raise ValueError('frozen_required_count')
        scan_ref=Path('scans')/profile;shutil.copytree(scanner_root/f'scanner-{short}-candidate-5',root/scan_ref)
        manifest['profiles'][profile]={'campaign_id':campaign_id,'inherited_campaign':campaign,'inheritance':inherited,'required_runs':required,'scan_ref':str(scan_ref)}
        capacity,inputs,capacity_plan=probe_suite(profile,archive/campaign/'candidate',runtime_config=config,runtime_profile_path=profile_path)
        pairs=[('capacity','candidate',capacity,capacity_plan,profile+'.'+case,0) for case in ('clean-a','secret-leak')]
        submitted=copy.deepcopy(compiled);submitted['subject_digest']=inherited['submitted_subject_digest']
        submitted['skill_digest']=digest_bytes(json.loads((archive/campaign/profile/'file-set.json').read_text())['files']['SKILL.md'].encode())
        pairs += [('formal',role,subject,plan,case,rep) for case,data in compiled['cases'].items() for rep in range(data['body']['repetitions']) for role,subject in [('submitted',submitted),('candidate',compiled)]]
        for kind,role,subject,current_plan,case,rep in pairs:
            entry_id=f'{kind}.{role}.{case}.{rep}'
            value={'kind':kind,'entry_id':entry_id,'profile':profile,'role':role,'case_id':case,'repetition':rep,'compiled':subject,'plan':current_plan,
                'config':config,'campaign_id':current_plan['body']['campaign_id'],'source_index_digest':digest_jcs(index)}
            if kind=='capacity':value['capacity_inputs']={k:base64.b64encode(v).decode() for k,v in inputs.items()}
            relative=Path('entries')/profile/(entry_id+'.json');entry=write_sealed(root/relative,value)
            verify_formal_entry(entry,image=image,source_digest=digest_jcs(index),model_port=port)
            manifest['entries'].append(str(relative))
    return write_sealed(root/'manifest.json',manifest)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--archive',type=Path,required=True);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--scanner-root',type=Path,required=True);parser.add_argument('--tokenizer',type=Path,required=True);parser.add_argument('--image',required=True);parser.add_argument('--port',type=int,default=11435);args=parser.parse_args()
    print(prepare(args.root,args.archive,args.source,args.scanner_root,args.tokenizer,args.image,args.port)['digest'])
