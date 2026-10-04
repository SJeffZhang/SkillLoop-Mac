"""Final Gate derives current campaign facts inside private role custody.

Only aggregate status and the frozen PublicReport cross to Controller/Reporter.
Full plans, session identities, reductions and CIResult stay in the Gate vault.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
from scripts.spec_v22_core import (execution_record,reduce_case,attach_execution_records,
    evaluate_gate,validate_plan,validate_suite,validate_required_run_manifest,build_ci_result)
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs,make_envelope
from skillloop.proxy.wire import make_control,validate_control
from skillloop.proxy.qualification_authority import current_authority
from skillloop.protection.authority import ProtectionAuthority
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.repair.budget import _remaining_whole_seconds
from skillloop.ci.qualification_store import QualificationIssuer


def _find(root,name):
    root=Path(root);found=[];count=0
    if root.is_symlink():raise PermissionError('campaign_gate_evidence_root')
    for directory,dirs,files in os.walk(root,followlinks=False):
        for item in dirs+files:
            path=Path(directory)/item;count+=1
            if path.is_symlink() or count>4096:raise ValueError('campaign_gate_evidence_inventory_bound')
            if item==name:found.append(path)
    if len(found)!=1:raise ValueError('campaign_gate_exact_original_evidence_required')
    return found[0]


def _task(intent,private):
    prefix='protected' if private else 'development';gid=21004 if private else 21001
    evaluation_path=_find('/'+prefix+'-evaluations',intent[7:]+'.json')
    review_path=_find('/'+prefix+'-reviews',intent[7:]+'.json')
    archive_path=_find('/'+prefix+'-archives',intent[7:]+'.archive.json')
    evaluation=read_owned(evaluation_path,uid=21004,gid=21004,limit=16777216)
    review=read_owned(review_path,uid=21005,gid=gid,limit=262144)
    archive=read_owned(archive_path,uid=21005,gid=gid,limit=262144)
    record=execution_record(evaluation['run_request'],evaluation['result'],
        evaluation['evidence_index'],evaluation['task_binding'])
    if (evaluation.get('kind')!='FormalTaskEvaluation' or evaluation.get('evaluator_uid')!=21004
            or evaluation.get('intent_digest')!=intent or evaluation['execution_record']!=record
            or review.get('kind')!='FormalTaskEvidenceReview' or review.get('gate_uid')!=21005
            or review.get('evidence_complete') is not True or review.get('intent_digest')!=intent
            or review.get('entry_digest')!=evaluation['entry_digest']
            or review.get('evaluation_digest')!=evaluation['digest']
            or review.get('execution_record_digest')!=record['digest']
            or any(review.get(k)!=evaluation.get(k) for k in ('runtime_capture_digest','authority_snapshot_digest'))
            or archive.get('kind')!='FormalTaskArchiveReview' or archive.get('gate_uid')!=21005
            or archive.get('complete') is not True or archive.get('task_review_digest')!=review['digest']
            or archive.get('intent_digest')!=intent or archive.get('entry_digest')!=evaluation['entry_digest']):
        raise ValueError('campaign_gate_actual_evaluation_review_archive_chain')
    return evaluation,{'evaluation_path':str(evaluation_path),'review_path':str(review_path),
        'archive_review_path':str(archive_path)}


def _archive_obligations(evaluations, paths):
    """Retain every reviewed task, including candidates removed by the roster.

    These are private archival obligations, not an assertion that the archive
    contains all campaign files. The later archive Gate must resolve the raw
    receipt/inventory and verify its bytes independently.
    """
    rows=[]
    for evaluation in evaluations:
        record=evaluation['execution_record'];pin=paths[record['digest']]
        request=evaluation['run_request']['body']
        private=pin['archive_review_path'].startswith('/protected-archives/')
        gid=21004 if private else 21001
        review=read_owned(pin['review_path'],uid=21005,gid=gid,limit=262144)
        archive=read_owned(pin['archive_review_path'],uid=21005,gid=gid,limit=262144)
        if (review['evaluation_digest']!=evaluation['digest']
                or archive['task_review_digest']!=review['digest']
                or archive['intent_digest']!=evaluation['intent_digest']
                or archive.get('complete') is not True):
            raise ValueError('campaign_archive_obligation_changed_after_task_review')
        rows.append({'intent_digest':evaluation['intent_digest'],
            'entry_digest':evaluation['entry_digest'],'execution_record_digest':record['digest'],
            'run_request_digest':evaluation['run_request']['digest'],
            'subject_digest':request['subject_digest'],'case_digest':request['case_digest'],
            'repetition_index':request['repetition_index'],
            'privacy_domain':'protected' if private else 'development',
            'evaluation_digest':evaluation['digest'],'task_review_digest':review['digest'],
            'archive_review_digest':archive['digest'],
            'archive_receipt_digest':archive['archive_receipt_digest'],
            'archive_inventory_digest':archive['inventory_digest'],**pin})
    if (len({r['intent_digest'] for r in rows})!=len(rows)
            or len({r['execution_record_digest'] for r in rows})!=len(rows)):
        raise ValueError('campaign_archive_obligation_duplicate_task')
    return sorted(rows,key=lambda r:r['intent_digest'])


def _chain(subject,compiled,plan,evaluations,context):
    selected=[e for e in evaluations if e['result']['body']['subject_digest']==subject]
    records={e['execution_record']['digest']:e['execution_record'] for e in selected}
    results={e['result']['digest']:e['result'] for e in selected}
    if len(records)!=len(selected) or len(results)!=len(selected):raise ValueError('campaign_gate_duplicate_execution')
    reductions=[]
    templates=list(compiled['cases'].values())
    for template in templates:
        rr=[r for r in records.values() if results[r['body']['result_digest']]['body']['case_digest']==template['digest']]
        if rr:reductions.append(attach_execution_records(reduce_case([results[r['body']['result_digest']] for r in rr],template),rr,results))
    gate=evaluate_gate(subject,compiled['suite'],plan,reductions,context)
    entries=[]
    for item in plan['body']['items']:
        if item['subject_digest']!=subject or item['requirement']!='required':continue
        matches=[r['digest'] for r in records.values() if all(results[r['body']['result_digest']]['body'][key]==item[key]
            for key in ('subject_digest','case_digest','repetition_index'))]
        entries.append({'item_id':item['item_id'],'run_record_digests':sorted(matches)})
    manifest=make_envelope('RequiredRunManifest',{'subject_digest':subject,'plan_digest':plan['digest'],'entries':entries})
    validate_required_run_manifest(manifest,plan,records,results)
    return {'context':context,'gate':gate,'plan':plan,'suite':compiled['suite'],
        'required_run_manifest':manifest,'records':records,'result_index':results,'templates':templates},reductions


def review_campaign():
    if os.geteuid()!=21005 or not {21001,21004}<=set(os.getgroups())|{os.getegid()}:
        raise PermissionError('campaign_gate_actual_private_role')
    job=read_owned('/assignment/job.json',uid=21001,gid=21005,limit=262144)
    fields={'kind','bindings','opaque_ref','whole_round_manifest_digest','deadline','digest'}
    if set(job)!=fields or job['kind']!='FormalCampaignGateAssignment':raise ValueError('campaign_gate_assignment')
    whole=read_round_manifest('/whole-round/manifest.json');bindings=job['bindings'];campaign=bindings['campaign']
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==campaign),None)
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
    if (scope is None or job['whole_round_manifest_digest']!=whole['digest'] or deadline.tzinfo is None
            or bindings['deployment_epoch']!=whole['deployment_epoch'] or datetime.now(timezone.utc)>=deadline):
        raise ValueError('campaign_gate_original_round_identity')
    from scripts.dgx_m6_repair import source_index
    if digest_jcs(source_index(Path(__file__).resolve().parents[2]))!=whole['source_digest']:
        raise ValueError('campaign_gate_actual_source_changed')
    authority=ProtectionAuthority(Path('/gate-authority'),readonly=True)
    record=authority.resolve_formal_bundle(campaign=campaign,opaque_ref=job['opaque_ref'])
    freeze=read_owned('/roster/freeze.json',uid=21005,gid=21001,limit=262144)
    development=read_owned('/roster/development-evidence.json',uid=21005,gid=21001,limit=16777216)
    devjob=read_owned('/development-assignment/job.json',uid=21001,gid=21005,limit=8388608)
    lifecycle=read_owned('/lifecycle/private-lifecycle.json',uid=21005,gid=21004,limit=262144)
    if (record['freeze_digest']!=freeze['digest'] or freeze['development_evidence_digest']!=development['digest']
            or development['assignment_digest']!=devjob['digest'] or record['subjects']!=bindings['subjects']
            or freeze['subjects']!=bindings['subjects'] or freeze['generation']!=bindings['generation']
            or record['config_digest']!=bindings['config_digest'] or record['trust_revision']!=bindings['trust_revision']
            or record['deadline']!=job['deadline'] or record['source_index_digest']!=whole['source_digest']
            or development['whole_round_manifest_digest']!=whole['digest']
            or lifecycle.get('kind')!='GatePrivateModelLifecycleReview' or lifecycle.get('gate_uid')!=21005
            or any(lifecycle.get(key)!=record[key] for key in ('campaign_id','deployment_epoch','config_digest','source_index_digest'))
            or lifecycle.get('factory_epoch_id')!=record['bundle']['epoch_id']
            or lifecycle.get('model_manifest_digest')!=record['config']['model_manifest_digest']
            or lifecycle.get('tokenizer_hashes')!=record['config']['tokenizer_hashes']
            or any(lifecycle.get(key) is not True for key in ('development_backend_stopped','private_backend_fresh','isolation_verified'))):
        raise ValueError('campaign_gate_actual_roster_factory_model_chain')
    compiled,plan=record['compiled'],record['private_plan']
    validate_plan(plan,compiled['suite']);validate_suite(compiled['suite'],list(compiled['cases'].values()),compiled['objectives'])
    evaluations=[];paths={};spent=list(devjob['spent_entries']);identities=set()
    for reference in devjob['executions']:
        evaluation,pin=_task(reference['intent_digest'],False)
        if evaluation['entry_digest']!=reference['entry_digest']:raise ValueError('campaign_gate_development_identity')
        evaluations.append(evaluation);paths[evaluation['execution_record']['digest']]=pin
    with authority.connect() as db:
        rows=db.execute('SELECT b.key,b.binding,s.state,s.result_digest,m.opaque_ref,m.runtime_action FROM formal_session_bindings b JOIN sessions s ON s.key=b.key LEFT JOIN formal_runtime_materializations m ON m.session_key=b.key WHERE s.epoch=?',(record['bundle']['epoch_id'],)).fetchall()
    from skillloop.protocol import decode_json
    for key,raw,state,result_digest,opaque,runtime_action in rows:
        pins=decode_json(raw)
        if state!='complete' or opaque is None or runtime_action is None or pins['campaign']!=campaign:
            raise ValueError('campaign_gate_private_delivery_unknown_or_incomplete')
        evaluation,pin=_task(pins['intent_digest'],True);body=evaluation['run_request']['body']
        identity=(body['subject_digest'],body['case_digest'],body['repetition_index'])
        if (identity!=(pins['subject'],pins['case'],pins['repetition']) or identity in identities
                or evaluation['execution_record']['digest']!=result_digest
                or evaluation['run_request']['digest']!=pins['request_digest'] or evaluation['entry_digest']!=pins['entry_digest']):
            raise ValueError('campaign_gate_private_actual_session_result')
        identities.add(identity);evaluations.append(evaluation);paths[result_digest]=pin;spent.append({'item_key':opaque,'attempt':0})
    required={(i['subject_digest'],i['case_digest'],i['repetition_index']) for i in plan['body']['items']
        if i['requirement']=='required' and i['phase']=='protected'}
    if identities!=required:raise ValueError('campaign_gate_full_private_matrix_missing')
    if len({e['intent_digest'] for e in evaluations})!=len(evaluations):raise ValueError('campaign_gate_duplicate_task')
    for e in evaluations:
        if (e['deployment_epoch']!=record['deployment_epoch'] or e['trust_revision']!=record['trust_revision']
                or e['run_request']['body']['config_digest']!=record['config_digest']):
            raise ValueError('campaign_gate_evaluation_epoch_or_configuration')
    snapshot=read_owned('/assignment/spending.json',uid=21001,gid=21005,limit=8388608)
    spending=snapshot['state'];reservation=spending['whole_round_cost_reservation']
    if (snapshot.get('kind')!='CampaignGateSpendingSnapshot' or snapshot['assignment_digest']!=job['digest']
            or reservation['manifest_digest']!=whole['digest'] or reservation['campaign']!=campaign
            or sorted(spending['executions'],key=lambda e:e['item_key'])!=sorted(spent,key=lambda e:e['item_key'])
            or len({e['item_key'] for e in spent})!=len(spent) or spending['victim_attempts']!=len(spent)
            or spending['retries']!=0 or spending['campaign_started_at']+28800!=deadline.timestamp()
            or reservation['victim_attempts']!=scope['reserved_victim_attempts']
            or reservation['victim_seconds']!=scope['victim_seconds'] or reservation['terminal_seconds']!=scope['terminal_seconds']
            or reservation['stages']!={stage:{'count':c['count'],'seconds':c['seconds']} for stage,c in scope['stages'].items()}):
        raise ValueError('campaign_gate_complete_original_spending')
    auxiliary=spending.get('auxiliary_executions',[])
    if len({c['operation_key'] for c in auxiliary})!=len(auxiliary):raise ValueError('campaign_gate_duplicate_auxiliary_spending')
    charged=len(spent)*scope['victim_seconds']
    for cost in spending.get('auxiliary_executions',[]):
        bound=scope['stages'][cost['stage']]
        if cost['reserved_cost']!={k:v for k,v in bound.items() if k!='count'}:raise ValueError('campaign_gate_auxiliary_bound_changed')
        charged+=bound['seconds']
    if charged!=spending['charged_wall_seconds'] or datetime.now(timezone.utc).timestamp()-spending['campaign_started_at']+_remaining_whole_seconds(spending,reservation)>28800:
        raise ValueError('campaign_gate_original_full_budget_exhausted')
    source_history=read_owned('/source-history/source-authority.json',uid=21003,gid=21005,limit=16777216)
    from skillloop.proxy.archive_projection import verify_source_history
    archived_sources=verify_source_history(source_history,campaign=campaign,epoch=record['deployment_epoch'],
        config_digest=record['config_digest'],trust_revision=record['trust_revision'])
    chains={};reductions=[];reviewed={};subjects=bindings['subjects']
    with current_authority('/authority-projection',epoch=record['deployment_epoch'],config_digest=record['config_digest'],
            trust_revision=record['trust_revision'],approval_digests=record['approval_digests']) as live:
        admitted={a['subject_digest']:a for a in live.get('source_admissions',[]) if a['campaign_id']==campaign}
        if archived_sources!=admitted:raise ValueError('campaign_gate_source_history_not_current_authority')
        if not set(record['approval_digests'])<={a['approval_digest'] for a in source_history['approvals']}:
            raise ValueError('campaign_gate_full_original_approval_history')
        heads=[h for h in live['plan_heads'] if h['campaign_id']==campaign]
        if len(heads)!=1 or heads[0]['plan_digest']!=freeze['development_plan_digest']:raise ValueError('campaign_gate_current_plan_head')
        for role,subject in subjects.items():
            selected=[e for e in evaluations if e['result']['body']['subject_digest']==subject]
            approvals={e['approval_digest'] for e in selected}
            scan=development['scans'].get(subject)
            if (not selected or len(approvals)!=1 or subject not in admitted or admitted[subject]['git_provenance'].get('package_bytes_verified') is not True or scan is None
                    or scan['scanner_report']['body']['status']!='complete'
                    or any(e['source_snapshot_digest']!=admitted[subject]['source_snapshot_digest'] for e in selected)):
                raise ValueError('campaign_gate_current_subject_source_scan_approval')
            high=sum(f['body']['severity'].lower() in {'high','critical'} for f in scan['findings'])
            # Facts below have each been independently derived from real
            # role-owned records, current authority and full original spending.
            context=make_envelope('GateContext',{'contract_approved':True,'approval_digest':next(iter(approvals)),
                'runtime_verified':True,'source_immutable':True,'scanner_complete':True,
                'authorization_verified':True,'evidence_verified':True,'unresolved_high_findings':high,
                'definite_failures':[],'incomplete_reasons':[],'config_digest':record['config_digest']})
            chains[role],cases=_chain(subject,compiled,plan,selected,context);reductions.extend(cases)
            reviewed[role]=[paths[e['execution_record']['digest']] for e in selected]
        expiries=[row[key] for row in live['approvals'] if row['approval_digest'] in record['approval_digests']
            for key in ('expires_at','factory_expires_at') if row[key] is not None]
        expiry=min(expiries,key=lambda x:datetime.fromisoformat(x.replace('Z','+00:00')))
    reductions=list({case['digest']:case for case in reductions}.values())
    ci=build_ci_result(chains['submitted']['gate'],chains.get('finalist',{}).get('gate'),reductions)
    vault=_directory('/private-result',21005,21005,0o700)
    obligations={'kind':'PrivateCampaignArchiveObligations','campaign_id':campaign,
        'deployment_epoch':record['deployment_epoch'],'config_digest':record['config_digest'],
        'assignment_digest':job['digest'],'whole_round_manifest_digest':whole['digest'],
        'development_assignment_digest':devjob['digest'],'roster_freeze_digest':freeze['digest'],
        'factory_epoch_id':record['bundle']['epoch_id'],
        'tasks':_archive_obligations(evaluations,paths),
        'spending_snapshot_digest':snapshot['digest'],
        'authority_snapshot_digest':authority.snapshot['digest'],
        'lifecycle_digest':lifecycle['digest'],
        'campaign_coverage_complete':False,'deletion_authorized':False}
    obligations['digest']=digest_jcs(obligations)
    _publish(vault/'archive-obligations.json',obligations,21005)
    facts={'whole-round':whole,'development-assignment':devjob,
        'development-evidence':development,'roster-freeze':freeze,
        'authority-snapshot':authority.snapshot,'model-lifecycle':lifecycle,'spending':snapshot,
        'source-history':source_history}
    # Preserve the actual facts reviewed by this Gate inside its own vault.
    # This copies objects, not live database permissions or Controller access.
    for name,value in facts.items():_publish(vault/('archive-fact-'+name+'.json'),value,21005)
    evidence={'kind':'FormalCampaignGateEvidence','assignment_digest':job['digest'],'bindings':bindings,
        'archive_obligations_digest':obligations['digest'],
        'archive_fact_digests':{name:value['digest'] for name,value in facts.items()},
        'chains':chains,'ci_result':ci,'authority_snapshot_digest':authority.snapshot['digest'],
        'spending_snapshot_digest':snapshot['digest'],'lifecycle_digest':lifecycle['digest']}
    evidence['digest']=digest_jcs(evidence)
    # Private case reductions and proof references are never written to the
    # Controller-readable completion or report.
    _publish(vault/'campaign-evidence.json',evidence,21005)
    issuable=all(chain['gate']['body']['verdict'] in {'pass','fail'} and not chain['gate']['body']['incomplete_reasons']
        and not chain['context']['body']['unresolved_high_findings'] for chain in chains.values())
    if issuable:
        issuer=QualificationIssuer('/eligibility/qualification.sqlite',deployment_epoch=record['deployment_epoch'],
            config_digest=record['config_digest'],authority_directory='/authority-projection',
            private_path='/private-result/proofs.sqlite')
        issuer.issue_campaign(campaign=campaign,generation=bindings['generation'],source_snapshot_digest=bindings['source_snapshot_digest'],
            trust_revision=bindings['trust_revision'],subjects=subjects,chains=chains,approval_expires_at=expiry,reviewed_tasks=reviewed)
    report=make_control('PublicReport',{'campaign_public_ref':campaign,
        'submitted_verdict':chains['submitted']['gate']['body']['verdict'],
        'candidate_verdict':chains['finalist']['gate']['body']['verdict'] if 'finalist' in chains else None,
        'coverage':'complete' if all(c['gate']['body']['coverage']['required_cases']==c['gate']['body']['coverage']['completed_cases'] and c['gate']['body']['coverage']['required_repetitions']==c['gate']['body']['coverage']['completed_repetitions'] for c in chains.values()) else 'incomplete',
        'reason_codes':[] if issuable else ['qualification_unavailable'],
        'evidence_opaque_refs':[job['opaque_ref']],'repair_value':'repair_value_not_demonstrated' if 'finalist' in chains else 'not_applicable'})
    validate_control(report)
    output=_directory('/public-result',21005,21001,0o750);_publish(output/(campaign[7:]+'.json'),report,21001)
    completion={'kind':'FormalCampaignGateCompletion','assignment_digest':job['digest'],'campaign_id':campaign,
        'qualification_issued':issuable,'report_digest':report['digest'],'production_ready':False}
    completion['digest']=digest_jcs(completion);_publish(output/'completion.json',completion,21001)
    return completion


if __name__=='__main__':
    os.umask(0o077);review_campaign()
