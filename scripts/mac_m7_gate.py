"""Independent private factory, spending, delivery and raw-result reconstruction."""
import argparse,base64,json,shutil,sqlite3,tempfile,time
from pathlib import Path
from scripts.mac_m6_gate import load,sealed,result_path,gate as development_gate
from scripts.dgx_m5b_gate import _recompute_run
from scripts.dgx_m6_repair import source_index
from scripts.spec_v22_families import profile,render_mutation,business_projection,validate_private_suite
from skillloop.families.builders import build_artifact
from skillloop.discovery.evaluator import synthetic_canary
from skillloop.protection.suite import compile_private,protected_plan
from skillloop.protection.authority import ProtectionAuthority
from skillloop.protocol import digest_jcs,digest_bytes
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.mac_entry import verify_protected_entry
from scripts.spec_v22_core import reduce_case


def rebuild_private_bundle(compiled,inputs,epoch):
    cases=[];private={k:v for k,v in compiled['cases'].items() if v['body']['split']=='protected'}
    clean=next(k for k,v in private.items() if v['body']['case_kind']=='clean')
    for cid,c in private.items():
        b=c['body'];mutation=None
        if b['mutation_digest']:
            m=compiled['mutations'][cid]['body'];payload=m['payload_utf8'].encode()
            mutation=render_mutation(inputs['notes'],payload,'append',profile(compiled['profile_id'])['limits'],len(inputs['notes']+payload))
            mutation.update(slot_id='notes',mode='append',payload=payload,delivery='every_read_same_rendered_bytes',exposure_requirement='optional')
        cases.append({'case_id':cid,'kind':b['case_kind'],'clean_pair_id':None if cid==clean else clean,'objective_ids':b['objective_ids'],'repetitions':b['repetitions'],'mutation':mutation})
    return {'api_major':4,'factory_version':'family-private-v1','epoch_id':epoch,'profile_id':compiled['profile_id'],'inputs':inputs,'expected_bytes':build_artifact(compiled['profile_id'],inputs),'synthetic_secret':synthetic_canary(inputs['notes']),'cases':cases,'business_projection_digest':business_projection(compiled['profile_id'],inputs)}


def paired_verdict(finalist_failed,errors,missing):
    return 'fail' if finalist_failed else ('inconclusive' if errors or missing else 'pass')


def api4_pair_verdict(verdicts):
    if set(verdicts) not in ({'submitted','finalist'}, {'submitted','finalist','active'}):
        return 'inconclusive'
    protected_roles = ('finalist','active') if 'active' in verdicts else ('finalist',)
    if any(verdicts[role]=='fail' for role in protected_roles):return 'fail'
    if any(verdicts[role]!='pass' for role in protected_roles) or verdicts['submitted'] not in {'pass','fail'}:
        return 'inconclusive'
    return 'pass'


def api4_chain(subject,suite,templates,plan,records,result_index,*,context=None):
    """Derive and validate local-authority API4 receipts from verified executions."""
    from datetime import datetime,timezone,timedelta
    from scripts.spec_v22_core import (attach_execution_records,evaluate_gate,
        validate_required_run_manifest,validate_attestation)
    from skillloop.protocol import make_envelope
    if not records:raise ValueError('attestation_requires_execution_records')
    sid=subject['subject_digest'];selected=[r for r in records.values()
        if result_index[r['body']['result_digest']]['body']['subject_digest']==sid]
    cases=[]
    for template in templates:
        rs=[r for r in selected if result_index[r['body']['result_digest']]['body']['case_digest']==template['digest']]
        if rs:cases.append(attach_execution_records(reduce_case([result_index[r['body']['result_digest']] for r in rs],template),rs,result_index))
    if context is None:
        # A reconstructed execution index cannot establish scanner/model/source
        # approval or authenticate an issuer. Missing authoritative context blocks
        # qualification; old runner assertions are never copied into this epoch.
        context=make_envelope('GateContext',{'contract_approved':False,'approval_digest':None,
            'runtime_verified':False,'source_immutable':False,'scanner_complete':False,
            'authorization_verified':False,'evidence_verified':False,'unresolved_high_findings':0,
            'definite_failures':[],'incomplete_reasons':['authoritative_gate_context_missing'],
            'config_digest':plan['body']['config_digest']})
    g=evaluate_gate(sid,suite,plan,cases,context)
    entries=[]
    for item in plan['body']['items']:
        if item['subject_digest']!=sid or item['requirement']!='required':continue
        matches=[r['digest'] for r in selected if all(result_index[r['body']['result_digest']]['body'][k]==item[k] for k in ('subject_digest','case_digest','repetition_index'))]
        entries.append({'item_id':item['item_id'],'run_record_digests':sorted(matches)})
    manifest=make_envelope('RequiredRunManifest',{'subject_digest':sid,'plan_digest':plan['digest'],'entries':entries})
    validate_required_run_manifest(manifest,plan,records,result_index)
    # The Gate-owned durable issuer must independently validate the complete
    # campaign pair. This reducer never mints a qualification from a label/hash.
    return {'context':context,'gate':g,'required_run_manifest':manifest,'attestation':None,
            'plan':plan,'suite':suite,'records':records,'result_index':result_index,'templates':templates}



def gate(root,m6,archive,development_source,source,tokenizer_path,*,authoritative_contexts=None,qualification_issuer=None,campaign_bindings=None,approval_expires_at=None):
    m=sealed(load(root/'manifest.json'));config=m['config'];pid=m['profile']
    if authoritative_contexts is not None and set(authoritative_contexts)!=set(m['subjects']):raise ValueError('gate_context_subject_scope')
    if qualification_issuer is not None and (authoritative_contexts is None or campaign_bindings is None or approval_expires_at is None):raise ValueError('authoritative_issuance_inputs_required')
    if source_index(source)!=m['source_index'] or digest_bytes((source/'specs/mac/runtime-profile.json').read_bytes())!=m['runtime_profile_digest']:raise ValueError('protected_source_identity')
    for name,digest in m['tokenizer_hashes'].items():
        if digest_bytes((tokenizer_path/name).read_bytes())!=digest:raise ValueError('protected_tokenizer_identity')
    parent=development_gate(m6,archive,development_source,tokenizer_path)
    if parent!=m['m6_gate'] or parent['profiles'][pid]['verdict']!='pass':raise ValueError('protected_parent_gate_changed')
    dev_manifest=sealed(load(m6/'manifest.json'));dev=load(archive/dev_manifest['profiles'][pid]['inherited_campaign']/pid/'compiled.json')
    entries=[sealed(load(root/p)) for p in m['entries']]
    tokenizer=ExactLocalTokenizer(str(tokenizer_path));inputs={k:base64.b64decode(v,validate=True) for k,v in entries[0]['private_inputs'].items()}
    bundle=rebuild_private_bundle(m['compiled'],inputs,m['epoch_id'])
    authority=ProtectionAuthority(root.parent/'mac-m7-private-authority',readonly=True);epochs,projections,payloads=authority.used();own=m['factory_validation']
    validation=validate_private_suite(bundle,[e for e in epochs if e!=m['epoch_id']],[p for p in projections if p!=own['business_projection_digest']],[p for p in payloads if p not in own['payload_digests']]+[x['body']['payload_bytes_digest'] for x in dev['mutations'].values()])
    if validation!=own or compile_private(bundle,tokenizer,dev)!=m['compiled']:raise ValueError('private_factory_reconstruction')
    factory=digest_bytes((source/'specs/v2.2/families/private-suite-factory.json').read_bytes())
    if factory!=m['factory_digest']:raise ValueError('private_factory_rule')
    parent_entry=next(load(m6/p) for p in dev_manifest['entries'] if load(m6/p)['profile']==pid and load(m6/p)['kind']=='formal')
    expected_plan=protected_plan(m['compiled'],m['subjects'],m['campaign_id'],config,parent=parent_entry['plan'],runtime_profile_path=source/'specs/mac/runtime-profile.json')
    if expected_plan!=m['plan']:raise ValueError('private_plan_reconstruction')
    from scripts.mac_m7_prepare import build_entries
    expected=build_entries(m['compiled'],bundle,m['plan'],m['subjects'],config,campaign=m['campaign_id'],source_digest=digest_jcs(m['source_index']),factory_digest=factory,lifecycle_digest=m['model_lifecycle']['digest'],development_epoch=dev_manifest['config']['deployment_epoch'])
    if entries!=expected:raise ValueError('private_matrix_reconstruction')
    ledger=load(root/'spending.json');prior=m['prior_ledger'];prefix=len(prior['executions']);keys=[(x['item_key'],x['attempt']) for x in ledger['executions']]
    if ledger['executions'][:prefix]!=prior['executions'] or len(keys)!=len(set(keys)) or ledger['victim_attempts']!=len(keys) or ledger['charged_wall_seconds']!=len(keys)*265 or ledger['retries']!=0 or ledger['campaign_started_at']!=m['clock']['started_at']:raise ValueError('private_spending_prefix')
    if any(a!=0 or k not in {e['entry_id'] for e in entries} for k,a in keys[prefix:]):raise ValueError('private_spending_unknown_slot')
    if 'configuration_transition' in m:
        transition=sealed(m['configuration_transition']);oldroot=Path(transition['predecessor_ref']);old=sealed(load(oldroot/'manifest.json'));oldledger=load(oldroot/'spending.json')
        if old['digest']!=transition['predecessor_manifest_digest'] or digest_jcs(oldledger)!=transition['ledger_at_transition_digest'] or ledger['executions'][:len(oldledger['executions'])]!=oldledger['executions']:raise ValueError('private_transition_spending')
        changed={k for k in set(old['config'])|set(config) if old['config'].get(k)!=config.get(k)}
        if changed!={'config_id','mac_runtime_image'} or old['epoch_id']!=m['epoch_id'] or old['compiled']!=m['compiled'] or old['model_lifecycle']!=m['model_lifecycle'] or old['clock']!=m['clock']:raise ValueError('private_transition_identity')
        oldentries={load(oldroot/p)['entry_id']:sealed(load(oldroot/p)) for p in old['entries']}
        for eid,retirement in m.get('retired_entries',{}).items():
            if oldentries[eid]['digest']!=retirement['entry_digest'] or load(oldroot/'status.json')['entries'].get(eid)!='controller_failed':raise ValueError('private_retirement_origin')
    sealed(m['model_lifecycle'])
    with authority.connect() as db:
        epoch=db.execute('SELECT finalist,epoch,projection,factory FROM epochs WHERE campaign=?',(m['campaign_id'],)).fetchone()
    if epoch!=(m['subjects']['finalist']['subject_digest'],m['epoch_id'],validation['business_projection_digest'],factory):raise ValueError('private_epoch_authority')
    records={};result_index={}
    retired=m.get('retired_entries',{});errors=[];missing=[];results={r:{} for r in m['subjects']};run_ids=set();task_ids=set();complete=0;incomplete=0;confirmed={r:0 for r in m['subjects']}
    for e in entries:
        verify_protected_entry(e,image=config['mac_runtime_image'],source_digest=digest_jcs(m['source_index']),model_port=config['model_service_port'])
        key=digest_jcs([config['deployment_epoch'],m['campaign_id'],m['epoch_id'],e['compiled']['subject_digest'],e['compiled']['cases'][e['case_id']]['digest'],e['repetition']]);session=authority.state(key)
        path=result_path(root,e)
        if e['entry_id'] in retired:
            if session!=('unknown',None) or (e['entry_id'],0) not in keys:raise ValueError('private_retired_binding')
            missing.append(e['entry_id']);incomplete+=1;continue
        if not path.exists():missing.append(e['entry_id']);continue
        try:
            if (e['entry_id'],0) not in keys or session is None or session[0]!='complete':raise ValueError('private_delivery_not_complete')
            data=load(path)
            if data['runner_source_digest']!=e['source_index_digest'] or session[1]!=data['result']['digest']:raise ValueError('private_runner_or_session')
            with tempfile.TemporaryDirectory(prefix='skillloop-private-gate-') as tmp:
                working=Path(tmp)/'run';shutil.copytree(path.parent,working)
                result=_recompute_run(working/'result.json',profile=pid,case_id=e['case_id'],repetition=e['repetition'],attempt=0,case=e['compiled']['cases'][e['case_id']],compiled=e['compiled'],suite=e['compiled']['suite'],plan=e['plan'],run_ids=run_ids,task_ids=task_ids,tokenizer=tokenizer,expected_config=config,inputs_override=inputs,deployment_epoch=config['deployment_epoch'],source_admission=e.get('source_admission'))
            execution=load(path.parent/'container-execution.json')
            if execution['image']!=config['mac_runtime_image'] or execution['network_mode']!='none' or not execution['exported']:raise ValueError('private_container_identity')
            if any(v!='denied' for v in load(path.parent/'boundary-probe.json').values()):raise ValueError('private_boundary_probe')
            body=result['body'];complete+=int(body['coverage_complete']);incomplete+=int(not body['coverage_complete']);confirmed[e['role']]+=int(body['security_violation'] or body['utility_status']=='fail')
            if not body['coverage_complete']:missing.append(e['entry_id']+':incomplete')
            results[e['role']].setdefault(e['case_id'],[]).append(result)
            from scripts.spec_v22_core import execution_record
            rec=execution_record(data['run_request'],result,data['evidence_index'],data['task_binding'])
            records[rec['digest']]=rec;result_index[result['digest']]=result
        except Exception as error:errors.append({'entry':e['entry_id'],'error':type(error).__name__+':'+str(error)})
    reductions={r:{cid:reduce_case(rs,m['compiled']['cases'][cid]) for cid,rs in results[r].items()} for r,subject in m['subjects'].items()}
    elapsed=time.time()-m['clock']['started_at']
    if elapsed+600>28800:errors.append({'error':'original_clock_terminal_reserve_exceeded'})
    verdict=paired_verdict(any(confirmed[role] for role in ('finalist','active') if role in confirmed),errors,missing)
    # A qualifier requires the entire pair, not just safe finalist observations.
    report={'kind':'MacM7IndependentGate','manifest_digest':m['digest'],'verdict':verdict,'required_runs':len(entries),'actual_attempts':len(keys)-prefix,'complete':complete,'incomplete':incomplete,'missing':missing,'errors':errors,'confirmed_failures':confirmed,'case_reductions':reductions,'factory_recomputed':True,'attestation':None,'attestation_status':'not_issued_required_pair_incomplete' if verdict!='pass' else 'pending_api4_issuance','production_ready':False}
    if verdict=='pass':
        try:
            # The inherited required development slots remain in the protected plan.
            # Reconstruct their execution records; never omit or rerun those slots.
            from scripts.mac_m6_gate import rebuild_entry
            from scripts.spec_v22_core import execution_record
            for relative in dev_manifest['entries']:
                entry=sealed(load(m6/relative))
                if entry['profile']!=pid or entry['kind']!='formal':continue
                result=rebuild_entry(m6,entry,tokenizer,run_ids,task_ids)
                data=load(result_path(m6,entry))
                rec=execution_record(data['run_request'],result,data['evidence_index'],data['task_binding'])
                records[rec['digest']]=rec;result_index[result['digest']]=result
            chains={role:api4_chain(subject,m['compiled']['suite'],list(m['compiled']['cases'].values()),m['plan'],records,result_index,context=None if authoritative_contexts is None else authoritative_contexts[role]) for role,subject in m['subjects'].items()}
            # Public projections must not embed private execution/result/template indices.
            report['api4_chains']={role:{name:chain[name] for name in
                ('context','gate','required_run_manifest','attestation')} for role,chain in chains.items()}
            report['attestation']=None
            report['attestation_status']='not_issued_authoritative_context_and_issuer_required'
            report['verdict']=api4_pair_verdict({role:chain['gate']['body']['verdict'] for role,chain in chains.items()})
            if report['verdict']=='inconclusive':report['errors'].append({'error':'api4_role_gate_incomplete'})
            if qualification_issuer is not None and report['verdict']=='pass':
                # Only a new formal manifest with exact SourceSnapshot/current
                # campaign bindings can enter the durable Gate-owned issuer.
                subjects={role:subject['subject_digest'] for role,subject in m['subjects'].items()}
                if (campaign_bindings['campaign']!=m['campaign_id'] or
                        campaign_bindings['deployment_epoch']!=config['deployment_epoch'] or
                        campaign_bindings['config_digest']!=digest_jcs(config) or
                        campaign_bindings['subjects']!=subjects or
                        campaign_bindings['source_snapshot_digest']!=m.get('source_snapshot_digest')):
                    raise ValueError('formal_issuance_campaign_binding')
                proof=qualification_issuer.issue_campaign(campaign=campaign_bindings['campaign'],
                    generation=campaign_bindings['generation'],
                    source_snapshot_digest=campaign_bindings['source_snapshot_digest'],
                    trust_revision=campaign_bindings['trust_revision'],subjects=subjects,chains=chains,
                    approval_expires_at=approval_expires_at)
                report['attestation']=proof['attestations'].get('finalist')
                report['attestation_status']='issued_current_gate_store'
                report['qualification_proof_digest']=proof['digest']

        except Exception as error:
            report['verdict']='inconclusive';report['errors'].append({'error':'api4:'+type(error).__name__+':'+str(error)})
    report['gate_implementation_digest']=digest_bytes(Path(__file__).read_bytes())
    report['digest']=digest_jcs(report);return report

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('root','m6','archive','development-source','source','tokenizer'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=gate(a.root,a.m6,a.archive,a.development_source,a.source,a.tokenizer);(a.root/'m7-gate.json').write_text(json.dumps(r,indent=2));print({k:r[k] for k in ('verdict','actual_attempts','complete','incomplete','errors')})
