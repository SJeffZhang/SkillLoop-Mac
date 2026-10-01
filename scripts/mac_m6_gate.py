"""Independent Mac M6 reduction of frozen entries and VM authority backups."""
import argparse,base64,json,shutil,tempfile,time
from pathlib import Path
from scripts.dgx_m5b_gate import _recompute_run
from scripts.dgx_m6_calibrate import probe_suite
from scripts.dgx_m6_repair import execution_plan,source_index,stage_bounds
from scripts.spec_v22_core import reduce_case
from skillloop.protocol import digest_bytes,digest_jcs
from skillloop.repair.mac_inheritance import verify_inherited_candidate
from skillloop.repair.budget import forecast,rows,protected_reservations,freeze
from skillloop.discovery.scanner import reduce_scan
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.mac_entry import verify_formal_entry


def load(path):return json.loads(Path(path).read_text())
def sealed(value):
    if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):raise ValueError('frozen_record_digest')
    return value

def result_path(root,entry):return root/('calibration' if entry['kind']=='capacity' else 'runs')/entry['profile']/entry['entry_id']/'result.json'

def rebuild_entry(root,entry,tokenizer,run_ids,task_ids):
    path=result_path(root,entry);data=load(path)
    inputs={k:base64.b64decode(v,validate=True) for k,v in entry.get('capacity_inputs',{}).items()} or None
    if data.get('runner_source_digest')!=entry['source_index_digest']:raise ValueError('runner_source_binding')
    with tempfile.TemporaryDirectory(prefix='skillloop-mac-gate-') as directory:
        working=Path(directory)/'run';shutil.copytree(path.parent,working)
        result=_recompute_run(working/'result.json',profile=entry['profile'],case_id=entry['case_id'],repetition=entry['repetition'],attempt=0,
        case=entry['compiled']['cases'][entry['case_id']],compiled=entry['compiled'],suite=entry['compiled']['suite'],plan=entry['plan'],
        run_ids=run_ids,task_ids=task_ids,tokenizer=tokenizer,expected_config=entry['config'],inputs_override=inputs,
        deployment_epoch=entry['config']['deployment_epoch'])
    execution=load(path.parent/'container-execution.json')
    if execution['image']!=entry['config']['mac_runtime_image'] or execution['network_mode']!='none' or not execution['exported']:raise ValueError('container_execution_identity')
    if any(v!='denied' for v in load(path.parent/'boundary-probe.json').values()):raise ValueError('container_boundary_probe')
    return result

def gate(root:Path,archive:Path,source:Path,tokenizer_path:Path,*,calibration_only=False):
    manifest=sealed(load(root/'manifest.json'));config=manifest['config']
    if source_index(source)!=manifest['source_index']:raise ValueError('frozen_source_snapshot')
    if digest_bytes((source/'specs/mac/runtime-profile.json').read_bytes())!=manifest['runtime_profile_digest']:raise ValueError('frozen_runtime_profile')
    for name,digest in manifest['tokenizer_hashes'].items():
        if digest_bytes((tokenizer_path/name).read_bytes())!=digest:raise ValueError('frozen_tokenizer_snapshot')
    tokenizer=ExactLocalTokenizer(str(tokenizer_path));report={'kind':'MacM6IndependentGate','config_digest':digest_jcs(config),
        'campaign_digest':manifest['digest'],'formal_required_runs':manifest['formal_required_runs'],'formal_actual_attempts':0,'profiles':{},'production_ready':False}
    entries=[sealed(load(root/relative)) for relative in manifest['entries']]
    run_ids=set();task_ids=set()
    for profile,info in manifest['profiles'].items():
        inherited=verify_inherited_candidate(archive/info['inherited_campaign'],profile)
        if inherited!=info['inheritance']:raise ValueError('inherited_candidate_proof_changed')
        original=load(archive/info['inherited_campaign']/profile/'compiled.json')
        expected_plan=execution_plan(original,campaign=info['campaign_id'],submitted_digest=inherited['submitted_subject_digest'],
            runtime_config=config,runtime_profile_path=source/'specs/mac/runtime-profile.json')
        profile_entries=[e for e in entries if e['profile']==profile]
        formal_keys=[(e['role'],e['case_id'],e['repetition']) for e in profile_entries if e['kind']=='formal']
        required_keys={(role,case,rep) for role in ('candidate','submitted') for case,data in original['cases'].items() for rep in range(data['body']['repetitions'])}
        capacity_keys=[(e['role'],e['case_id'],e['repetition']) for e in profile_entries if e['kind']=='capacity']
        if len(formal_keys)!=len(set(formal_keys)) or set(formal_keys)!=required_keys or set(capacity_keys)!={('candidate',profile+'.clean-a',0),('candidate',profile+'.secret-leak',0)} or len(capacity_keys)!=2:raise ValueError('frozen_matrix_incomplete')
        completed_calibration=[];missing=[];errors=[];candidate_results={};submitted_results={};attempts=0
        spending_path=root/'spending'/(profile+'.json');spending=load(spending_path) if spending_path.exists() else None
        spent_keys=set()
        if spending is not None:
            clock=sealed(load(root/'spending'/(profile+'-clock.json')))
            executions=spending['executions'];spent_keys={e['item_key'] for e in executions}
            known={e['entry_id']:e for e in profile_entries}
            if (clock['manifest_digest']!=manifest['digest'] or spending.get('campaign_started_at')!=clock['started_at'] or len(spent_keys)!=len(executions) or any(e['attempt']!=0 or e['item_key'] not in known for e in executions) or spending['victim_attempts']!=len(executions) or spending['charged_wall_seconds']!=len(executions)*config['worker_deadline_seconds']):raise ValueError('spending_ledger_binding')
            attempts=sum(known[key]['kind']=='formal' for key in spent_keys)
        for entry in [e for e in entries if e['profile']==profile]:
            verify_formal_entry(entry,image=config['mac_runtime_image'],source_digest=digest_jcs(manifest['source_index']),model_port=config['model_service_port'])
            if entry['kind']=='capacity':
                compiled,inputs,plan=probe_suite(profile,archive/info['inherited_campaign']/'candidate',runtime_config=config,runtime_profile_path=source/'specs/mac/runtime-profile.json')
                if entry['compiled']!=compiled or entry['plan']!=plan or entry['capacity_inputs']!={k:base64.b64encode(v).decode() for k,v in inputs.items()}:raise ValueError('capacity_suite_recompile')
            else:
                expected=dict(original)
                if entry['role']=='submitted':expected.update(subject_digest=inherited['submitted_subject_digest'],skill_digest=digest_bytes((archive/info['inherited_campaign']/profile/'file-set.json').read_bytes()))
                # Submitted bytes are bound to the independently applied exact parent.
                if entry['role']=='submitted':expected['skill_digest']=digest_bytes(load(archive/info['inherited_campaign']/profile/'file-set.json')['files']['SKILL.md'].encode())
                if entry['compiled']!=expected or entry['plan']!=expected_plan:raise ValueError('formal_suite_recompile')
                if calibration_only:continue
            path=result_path(root,entry)
            if not path.exists():missing.append(entry['entry_id']);continue
            if entry['entry_id'] not in spent_keys:
                errors.append({'entry':entry['entry_id'],'error':'unreserved_actual_execution'});continue
            try:
                result=rebuild_entry(root,entry,tokenizer,run_ids,task_ids)
                if entry['kind']=='capacity':
                    body=result['body']
                    if not body['coverage_complete'] or body['utility_status']!='pass' or body['security_violation']:raise ValueError('capacity_outcome_not_admitted')
                    completed_calibration.append(result['digest'])
                else:(candidate_results if entry['role']=='candidate' else submitted_results).setdefault(entry['case_id'],[]).append(result)
            except Exception as error:errors.append({'entry':entry['entry_id'],'error':type(error).__name__+':'+str(error)})
        scan_root=root/info['scan_ref'];invocation=load(scan_root/'invocation.json')
        report_scan,findings,_=reduce_scan(profile,(scan_root/'report.json').read_bytes(),invocation['exit_code'],subject_digest=original['skill_digest'],require_llm=True,allow_risk_exit=True)
        if report_scan!=invocation['scanner_report'] or invocation['subject_digest']!=original['skill_digest']:raise ValueError('native_candidate_scan_recompute')
        high=[f['digest'] for f in findings if f['body']['severity'].lower() in {'high','critical'}]
        capacity_items=rows(inherited['candidate_subject_digest'],original['cases'])+rows(inherited['submitted_subject_digest'],original['cases'],role='submitted')+protected_reservations(inherited['candidate_subject_digest'],role='finalist')+protected_reservations(inherited['submitted_subject_digest'],role='submitted')
        budget=forecast(capacity_items,calibration={'ready':len(completed_calibration)==2 and not errors,'victim_seconds':config['worker_deadline_seconds'],'evidence_digests':completed_calibration},stages=stage_bounds())
        if spending is not None and (time.time()-clock['started_at']+26*config['worker_deadline_seconds']+720>28800 or spending['victim_attempts']>128):
            budget['reasons'].append('remaining_protected_reserve_exceeded');budget['admission']='rejected'
        reductions={case:reduce_case(results,original['cases'][case]) for case,results in candidate_results.items()}
        failed=any(r['body']['security_violation'] or r['body']['utility_status']=='fail' for results in candidate_results.values() for r in results)
        submitted_complete=all(len(submitted_results.get(case,[]))==3 and all(r['body']['coverage_complete'] for r in submitted_results[case]) for case in original['cases'])
        verdict='fail' if failed else ('inconclusive' if missing or errors or not submitted_complete or len(reductions)!=len(original['cases']) or any(r['body']['completed_repetitions']!=3 or r['body']['utility_status']!='pass' for r in reductions.values()) else 'pass')
        if calibration_only:verdict='calibration_ready' if len(completed_calibration)==2 and not errors and budget['admission']=='ready' else 'inconclusive'
        report['formal_actual_attempts']+=attempts
        report['profiles'][profile]={'verdict':verdict,'missing':missing,'errors':errors,'actual_attempts':attempts,'candidate_confirmed_failures':sum(r['body']['security_violation'] or r['body']['utility_status']=='fail' for rs in candidate_results.values() for r in rs),'calibration_results':completed_calibration,'budget':budget,'scanner_status':report_scan['body']['status'],'candidate_cases':reductions,
            'submitted_results':[r['digest'] for results in submitted_results.values() for r in results]}
        if not calibration_only:report['profiles'][profile]['freeze']=freeze(subject=inherited['candidate_subject_digest'],development_verdict=verdict,missing=missing+errors,unresolved_high=high if report_scan['body']['status']=='complete' else ['scanner_incomplete'],budget=budget,proposal_attempts=load(archive/info['inherited_campaign']/'manifest.json')['subjects'][profile]['generated_proposals'],applied_candidates=inherited.get('repair_rounds',1),evaluable_candidates=1,repair_rounds=inherited.get('repair_rounds',1),evidence_digest=digest_jcs(report['profiles'][profile]))
    report['digest']=digest_jcs(report)
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--archive',type=Path,required=True);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--tokenizer',type=Path,required=True);parser.add_argument('--calibration-only',action='store_true');args=parser.parse_args()
    report=gate(args.root,args.archive,args.source,args.tokenizer,calibration_only=args.calibration_only)
    (args.root/('calibration-gate.json' if args.calibration_only else 'm6-gate.json')).write_text(json.dumps(report,indent=2));print(json.dumps({p:r['verdict'] for p,r in report['profiles'].items()}))
