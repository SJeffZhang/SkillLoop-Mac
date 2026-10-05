"""Controller produces current Gate inputs from committed development tasks.

No task or model is called here. A partial phase cannot be turned into a
complete roster assignment; the independent Gate still reviews every result.
"""
from datetime import datetime,timezone
import os,time
from pathlib import Path

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs,canonical_json_line
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.protected_flow import _controller_record


def produce_roster_assignment(*,policy_path,expected_policy_digest,campaign,assignment_directory,executor,registry,ledger,whole):
    if os.geteuid()!=21001:raise PermissionError('roster_assignment_actual_controller')
    recipe=read_owned(policy_path,uid=21010,gid=21001,limit=2097152)
    fields={'kind','campaign_digest','whole_round_manifest_digest','phase_path',
        'application_review_paths','scans','finalist_selection','digest'}
    if (set(recipe)!=fields or recipe['kind']!='FrozenDevelopmentRosterProduction'
            or recipe['digest']!=expected_policy_digest or recipe['campaign_digest']!=campaign
            or recipe['whole_round_manifest_digest']!=whole['digest']
            or recipe['finalist_selection'] not in {'submitted_only','latest_candidate'}
            or type(recipe['application_review_paths']) is not list
            or len(recipe['application_review_paths'])>2 or type(recipe['scans']) is not list
            or not 1<=len(recipe['scans'])<=4):
        raise ValueError('roster_assignment_original_production_recipe')
    root=_directory(assignment_directory,21001,21005,0o750)
    # A lost publication response returns the same produced object. It does
    # not acquire a new budget slot, reconstruct a new task or modify inputs.
    if (root/'production.json').exists():
        receipt=read_owned(root/'production.json',uid=21001,gid=21005,limit=262144)
        job=read_owned(root/'job.json',uid=21001,gid=21005,limit=8388608)
        if (receipt.get('kind')!='ControllerDevelopmentRosterProduced'
                or receipt.get('production_policy_digest')!=recipe['digest']
                or receipt.get('assignment_digest')!=job['digest']
                or receipt.get('budget_closure')!='within_original_budget'
                or job.get('kind')!='FormalDevelopmentRosterAssignment'
                or job.get('bindings',{}).get('campaign')!=campaign
                or job.get('whole_round_manifest_digest')!=whole['digest']):
            raise ValueError('roster_assignment_original_production_conflict')
        return job,recipe['digest']
    if any(root.iterdir()):raise RuntimeError('roster_assignment_partial_publication_unknown')
    began=time.monotonic()
    cost=ledger.consume_auxiliary(manifest=whole,campaign=recipe['campaign_digest'],stage='repair_pairing',
        operation_key='roster-assignment-'+recipe['digest'][7:],seconds=30,
        input_tokens=0,output_tokens=0,disk_bytes=8388608)
    phase=read_owned(recipe['phase_path'],uid=21010,gid=21001,limit=8388608)
    summary=executor.recover_completed(phase)
    from skillloop.discovery.phase_chain import development_parent
    chain=[];current=phase;seen=set()
    while current is not None:
        if current['digest'] in seen or len(chain)>=32:
            raise ValueError('roster_assignment_original_phase_chain_capacity')
        seen.add(current['digest']);chain.append(current);current=development_parent(current)
    units=[(p,u) for p in reversed(chain) for u in p['entries']]
    if not units or len(units)>128:raise ValueError('roster_assignment_full_task_capacity')
    config=units[-1][1]['entry']['config'];compiled=units[-1][1]['entry']['compiled']
    items=[i for i in phase['plan']['body']['items'] if i['requirement']=='required']
    executions=[];approvals=set();spent=[]
    for original,unit in units:
        entry=unit['entry'];token='task-'+digest_jcs(entry['entry_id'])[7:]
        journal=executor.directory/original['digest'][7:]
        prepared=_controller_record(journal/(token+'.prepared.json'))
        lease=_controller_record(journal/(token+'.lease.json'))
        selected=[i for i in items if i['subject_digest']==entry['compiled']['subject_digest']
            and i['case_digest']==entry['compiled']['cases'][entry['case_id']]['digest']
            and i['repetition_index']==entry['repetition'] and i['subject_role']==entry['role']]
        if len(selected)!=1 or entry['config']!=config:
            raise ValueError('roster_assignment_current_full_plan_task_binding')
        executions.append({'item_id':selected[0]['item_id'],'entry_id':entry['entry_id'],
            'entry_digest':entry['digest'],'intent_digest':prepared['intent_digest']})
        approvals.add(lease['started']['approval_digest'])
        spent.append({'item_key':entry['entry_id'],'attempt':0})
    if ({r['item_id'] for r in executions}!={i['item_id'] for i in items}
            or len(executions)!=len(items) or ledger.read()['executions']!=spent):
        raise ValueError('roster_assignment_original_spent_full_coverage')
    applications=[];last=None
    for path in recipe['application_review_paths']:
        review=read_owned(path,uid=21005,gid=21001,limit=262144)
        if (review.get('kind')!='GateBoundedCandidateApplication'
                or review.get('campaign_id')!=recipe['campaign_digest']
                or review.get('config_digest')!=digest_jcs(config)
                or review.get('application_verified') is not True):
            raise ValueError('roster_assignment_actual_application_review')
        applications.append({'assignment_digest':review['assignment_digest'],'review_digest':review['digest']})
        last=review['candidate_bundle_digest']
    if recipe['finalist_selection']=='latest_candidate' and last is None:
        raise ValueError('roster_assignment_no_actual_candidate')
    scans=[]
    for pin in recipe['scans']:
        fields={'subject_digest','receipt_path','review_path'}
        if type(pin) is not dict or set(pin) not in (fields,fields|{'semantic_directory'}):
            raise ValueError('roster_assignment_actual_scan_locator')
        receipt=read_owned(pin['receipt_path'],uid=21001,gid=21001,limit=262144)
        review=read_owned(pin['review_path'],uid=21005,gid=21001,limit=262144)
        snapshot=read_owned(Path(pin['receipt_path']).parent/'source-snapshot.json',uid=21001,gid=21001,limit=262144)
        if (receipt.get('kind')!='FormalScanEvidence' or review.get('kind')!='ScanEvidenceReview'
                or review.get('export_receipt_digest')!=receipt['digest']
                or review.get('evidence_complete') is not True
                or receipt['source_snapshot_digest']!=snapshot['digest']):
            raise ValueError('roster_assignment_actual_scan_evidence')
        value={'subject_digest':pin['subject_digest'],'package_digest':snapshot['body']['skill_digest'],
            'receipt_digest':receipt['digest'],'review_digest':review['digest']}
        if 'semantic_directory' in pin:value['semantic_directory']=pin['semantic_directory']
        scans.append(value)
    with registry.development_scope(campaign=recipe['campaign_digest']) as state:
        job={'kind':'FormalDevelopmentRosterAssignment','bindings':state['bindings'],'config':config,
            'whole_round_manifest_digest':whole['digest'],'development':compiled,'plan':phase['plan'],
            'executions':executions,'applications':applications,'scans':scans,
            'finalist':last if recipe['finalist_selection']=='latest_candidate' else None,
            'repair_rounds_allowed':config['repair_rounds_allowed'],'approval_digests':sorted(approvals),
            'spent_entries':spent,'deadline':state['deadline']}
        job['digest']=digest_jcs(job)
        if (digest_jcs(config)!=state['bindings']['config_digest']
                or phase['campaign_deadline']!=state['deadline']
                or len(canonical_json_line(job))>8388608):
            raise ValueError('roster_assignment_original_registry_clock_and_capacity')
        elapsed=time.monotonic()-began
        if elapsed>30 or (datetime.fromisoformat(state['deadline'].replace('Z','+00:00'))-
                datetime.now(timezone.utc)).total_seconds()<=120:
            raise TimeoutError('roster_assignment_original_production_budget')
        _publish(root/'job.json',job,21005)
        receipt={'kind':'ControllerDevelopmentRosterProduced',
            'production_policy_digest':recipe['digest'],'assignment_digest':job['digest'],
            'original_phase_summary_digest':summary['digest'],'spending':cost,'elapsed_seconds':elapsed,
            'budget_closure':'within_original_budget'}
        receipt['digest']=digest_jcs(receipt)
        _publish(root/'production.json',receipt,21005)
    return job,recipe['digest']
