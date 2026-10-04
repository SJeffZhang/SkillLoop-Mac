"""Prepare private Mac protection entries without making any model requests."""
import argparse,base64,json,os,time
from pathlib import Path
from scripts.mac_m6_gate import load,sealed,gate
from scripts.mac_m6_matrix import save
from scripts.dgx_m6_repair import source_index
from scripts.spec_v22_families import generate_private_suite,validate_private_suite
from skillloop.protocol import digest_jcs,digest_bytes
from skillloop.protection.mac_admission import admit_profile
from skillloop.protection.authority import ProtectionAuthority
from skillloop.protection.suite import compile_private,protected_plan
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.families.fixtures import load_example_skill
from skillloop.runtime.mac_entry import verify_protected_entry


def build_entries(compiled,bundle,plan,subjects,config,*,campaign,source_digest,factory_digest,lifecycle_digest,development_epoch,
                  development_suite_epoch_id=None):
    entries=[]
    normalized={('active_baseline' if r=='active' else r):s for r,s in subjects.items()}
    if len(normalized)!=len(subjects):raise ValueError('protected_duplicate_role_alias')
    reserved_items=[i for i in plan['body']['items'] if i['phase']=='protected' and i['requirement']=='required']
    if config.get('whole_flow_required'):
        if any(s.get('source_admission') is None for s in normalized.values()):
            raise ValueError('protected_formal_sources_required')
    # Pair the same private case/repetition before moving to the next item.
    for cid,case in compiled['cases'].items():
        if case['body']['split']!='protected':continue
        for repetition in range(case['body']['repetitions']):
            for role,subject in normalized.items():
                matching=[i for i in reserved_items if i['subject_role']==role
                    and i['subject_digest']==subject['subject_digest'] and i['case_digest']==case['digest']
                    and i['repetition_index']==repetition]
                # Identical submitted/finalist/active aliases reuse the actual
                # plan identity; a label never creates another private run.
                if not matching:continue
                if len(matching)!=1:raise ValueError('protected_duplicate_required_item')
                entry={'kind':'protected','entry_id':'protected.'+role+'.'+cid+'.'+str(repetition),'profile':compiled['profile_id'],'case_id':cid,'repetition':repetition,'role':role,'config':config,'campaign_id':campaign,'epoch_id':bundle['epoch_id'],'compiled':{**compiled,'subject_digest':subject['subject_digest'],'skill_digest':subject['skill_digest']},'plan':plan,'source_index_digest':source_digest,'subject_root':subject['skill_root'],'approval_factory_digest':factory_digest,'private_inputs':{k:base64.b64encode(v).decode() for k,v in bundle['inputs'].items()},'private_expected_digest':digest_bytes(bundle['expected_bytes']),'model_lifecycle_digest':lifecycle_digest,'development_epoch':development_epoch}
                if config.get('whole_flow_required'):
                    entry['development_suite_epoch_id']=development_suite_epoch_id
                if subject.get('source_admission') is not None:
                    from skillloop.loader import validate_source_admission
                    validate_source_admission(subject['source_admission'],config,subject['subject_digest'])
                    entry['source_admission']=subject['source_admission']
                entry['digest']=digest_jcs(entry)
                verify_protected_entry(entry,image=config['mac_runtime_image'],source_digest=source_digest,model_port=config['model_service_port'])
                entries.append(entry)
    expected_items = [item for item in plan['body']['items'] if item['phase']=='protected' and item['requirement']=='required']
    actual = {(e['role'],e['compiled']['subject_digest'],e['compiled']['cases'][e['case_id']]['digest'],e['repetition']) for e in entries}
    reserved = {(i['subject_role'],i['subject_digest'],i['case_digest'],i['repetition_index']) for i in expected_items}
    if len(actual)!=len(entries) or len(reserved)!=len(expected_items) or actual!=reserved:
        raise ValueError('protected_matrix_shape')
    return entries


def prepare(out,m6,archive,development_source,source,tokenizer,lifecycle,image,profile='orders_total'):
    if out.exists():raise ValueError('private_activity_exists_recover_only')
    os.umask(0o077)
    manifest=sealed(load(m6/'manifest.json'))
    parent_gate=gate(m6,archive,development_source,tokenizer)
    clock=sealed(load(m6/'spending'/(profile+'-clock.json')));ledger=load(m6/'spending'/(profile+'.json'))
    previous=[sealed(load(m6/p)) for p in manifest['entries']]
    admission=admit_profile(parent_gate,manifest,clock,ledger,profile=profile,expected_executions=[{'item_key':e['entry_id'],'attempt':0} for e in previous if e['profile']==profile],at_unix_ms=int(time.time()*1000))
    if admission['admission']!='ready':raise ValueError('protected_remaining_budget_rejected')
    life=sealed(load(lifecycle))
    if life['status']!='ready' or life['development_service_running'] or life['port']==manifest['config']['model_service_port']:raise ValueError('private_model_lifecycle_not_ready')
    config={**manifest['config'],'config_id':'mac-m7-ollama-qwen38-mxfp8-orders-v1','deployment_epoch':life['deployment_epoch'],'model_service_port':life['port'],'mac_runtime_image':image}
    info=manifest['profiles'][profile];development=load(archive/info['inherited_campaign']/profile/'compiled.json')
    authority=ProtectionAuthority(out.parent/'mac-m7-private-authority');epochs,projections,payloads=authority.used()
    payloads += [v['body']['payload_bytes_digest'] for v in development['mutations'].values()]
    bundle=generate_private_suite(profile,os.urandom(32));validation=validate_private_suite(bundle,epochs,projections,payloads)
    compiled=compile_private(bundle,ExactLocalTokenizer(str(tokenizer)),development)
    submitted=m6/'submitted'/profile;candidate=archive/info['inherited_campaign']/'candidate'
    subjects={r:{'subject_digest':info['inheritance'][k],'skill_digest':digest_bytes(load_example_skill(profile,root=root)),'skill_root':str(root.resolve())} for r,k,root in [('submitted','submitted_subject_digest',submitted),('finalist','candidate_subject_digest',candidate)]}
    parent=next(e['plan'] for e in previous if e['profile']==profile and e['kind']=='formal')
    plan=protected_plan(compiled,subjects,info['campaign_id'],config,parent=parent,runtime_profile_path=source/'specs/mac/runtime-profile.json')
    factory=digest_bytes((source/'specs/v2.2/families/private-suite-factory.json').read_bytes())
    index=source_index(source)
    entries=build_entries(compiled,bundle,plan,subjects,config,campaign=info['campaign_id'],source_digest=digest_jcs(index),factory_digest=factory,lifecycle_digest=life['digest'],development_epoch=manifest['config']['deployment_epoch'])
    out.mkdir(mode=0o700)
    opaque=authority.create_epoch(campaign=info['campaign_id'],finalist=subjects['finalist']['subject_digest'],validation=validation,factory_digest=factory)
    paths=[]
    for entry in entries:
        path=Path('entries')/profile/(entry['entry_id']+'.json');save(out/path,entry);os.chmod(out/path,0o400);paths.append(str(path))
    record={'kind':'MacM7PrivateActivity','profile':profile,'campaign_id':info['campaign_id'],'config':config,'source_index':index,'runtime_profile_digest':digest_bytes((source/'specs/mac/runtime-profile.json').read_bytes()),'tokenizer_hashes':manifest['tokenizer_hashes'],'m6_manifest_digest':manifest['digest'],'m6_gate':parent_gate,'admission':admission,'clock':clock,'prior_ledger':ledger,'compiled':compiled,'plan':plan,'subjects':subjects,'epoch_id':bundle['epoch_id'],'opaque_ref':opaque,'factory_digest':factory,'factory_validation':validation,'model_lifecycle':life,'entries':paths,'production_ready':False}
    record['digest']=digest_jcs(record);save(out/'manifest.json',record);os.chmod(out/'manifest.json',0o400)
    save(out/'spending.json',ledger)
    save(out/'status.json',{'phase':'prepared','required_runs':len(entries),'actual_attempts':0,'complete':0,'incomplete':0,'entries':{},'manifest_digest':record['digest']})
    return record

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('out','m6','archive','development-source','source','tokenizer','lifecycle'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--image',required=True);a=p.parse_args();prepare(a.out,a.m6,a.archive,a.development_source,a.source,a.tokenizer,a.lifecycle,a.image)
