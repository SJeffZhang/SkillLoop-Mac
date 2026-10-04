"""Actual Gate freezes a complete development roster before Factory release.

The Controller may nominate a finalist. It cannot certify that finalist's
results, substitute static scanning for semantic coverage, or omit a required
development item. This receipt grants no qualification or Git source admission.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat

from scripts.spec_v22_core import (execution_record, reduce_case, validate_plan,
                                  validate_required_run_manifest, validate_suite)
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.discovery.scanner import reduce_scan
from skillloop.protocol import canonical_json_line, digest_bytes, digest_jcs, make_envelope, validate_envelope
from skillloop.proxy.qualification_authority import current_authority
from skillloop.runtime.round_manifest import read_round_manifest


def _name(value):
    if type(value) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('roster_gate_digest_path')
    return value[7:] + '.json'


def _raw(path, limit):
    """Read an explicit Controller grant, not the scanner's private directory."""
    from skillloop.discovery.raw_evidence import read_granted_raw
    return read_granted_raw(path, uid=21001, gid=21001, limit=limit)


def _write(root, name, value):
    info=root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21005 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('roster_gate_output_custody')
    value={**value,'digest':digest_jcs(value)}
    raw=canonical_json_line(value)
    if len(raw)>16777216:raise ValueError('roster_gate_output_capacity')
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,21001);os.fchmod(stream.fileno(),0o640)
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return value


def freeze_roster(*,assignment_path,whole_round_manifest_path,evaluation_directory,
                  task_review_directory,application_directory,scan_directory,
                  scan_review_directory,authority_directory,output_directory):
    if os.geteuid()!=21005 or not {21001,21004}<=set(os.getgroups())|{os.getegid()}:
        raise PermissionError('roster_gate_actual_isolated_role_required')
    job=read_owned(assignment_path,uid=21001,gid=21005,limit=8388608)
    fields={'kind','bindings','config','whole_round_manifest_digest','development',
            'plan','executions','applications','scans','finalist',
            'repair_rounds_allowed','approval_digests','spent_entries','deadline','digest'}
    if (set(job)!=fields or job['kind']!='FormalDevelopmentRosterAssignment'
            or type(job['repair_rounds_allowed']) is not int
            or job['repair_rounds_allowed'] not in (0,1,2)
            or type(job['executions']) is not list or not 1<=len(job['executions'])<=128
            or type(job['applications']) is not list
            or len(job['applications'])>job['repair_rounds_allowed']
            or any(type(a) is not dict or set(a)!={'assignment_digest','review_digest'} for a in job['applications'])
            or len({a['assignment_digest'] for a in job['applications']})!=len(job['applications'])
            or type(job['scans']) is not list or len(job['scans'])>4):
        raise ValueError('roster_gate_assignment_shape')
    whole=read_round_manifest(whole_round_manifest_path);bindings=job['bindings']
    if (type(bindings) is not dict or set(bindings)!={'campaign','generation','deployment_epoch',
            'config_digest','source_snapshot_digest','trust_revision','subjects'}
            or type(bindings['subjects']) is not dict or 'submitted' not in bindings['subjects']
            or set(bindings['subjects'])-{'submitted','active'}):
        raise ValueError('roster_gate_original_registry_binding_shape')
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==bindings['campaign']),None)
    config_digest=digest_jcs(job['config'])
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
    if (scope is None or whole['digest']!=job['whole_round_manifest_digest']
            or bindings['config_digest']!=config_digest
            or bindings['deployment_epoch']!=whole['deployment_epoch']
            or deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline
            or job['config'].get('whole_flow_required') is not True):
        raise ValueError('roster_gate_original_round_binding')
    if (type(job['config'].get('repair_rounds_allowed')) is not int
            or job['config']['repair_rounds_allowed']!=job['repair_rounds_allowed']):
        raise ValueError('roster_gate_original_repair_round_allowance')
    from scripts.dgx_m6_repair import source_index
    if digest_jcs(source_index(Path(__file__).resolve().parents[2]))!=whole['source_digest']:
        raise ValueError('roster_gate_current_source_changed')
    compiled=job['development'];plan=job['plan'];suite=compiled['suite']
    validate_plan(plan,suite)
    validate_suite(suite,list(compiled['cases'].values()),compiled['objectives'])
    if (suite['body']['visibility']!='public_dev' or compiled['profile_id']!=scope['profile']
            or plan['body']['campaign_id']!=bindings['campaign'] or plan['body']['phase']!='dev'
            or plan['body']['config_digest']!=config_digest):
        raise ValueError('roster_gate_complete_public_development_plan')
    required={i['item_id']:i for i in plan['body']['items'] if i['requirement']=='required'}
    if (any(i['phase']!='dev' for i in required.values())
            or any(set(x)!={'item_id','entry_id','entry_digest','intent_digest'} for x in job['executions'])
            or len({x['item_id'] for x in job['executions']})!=len(job['executions'])
            or {x['item_id'] for x in job['executions']}!=set(required)
            or len({x['intent_digest'] for x in job['executions']})!=len(job['executions'])):
        raise ValueError('roster_gate_required_or_executed_item_omitted')
    spent=job['spent_entries']
    if (type(spent) is not list or len(spent)!=len(job['executions'])
            or any(type(s) is not dict or set(s)!={'item_key','attempt'} or s['attempt']!=0 for s in spent)
            or len({s['item_key'] for s in spent})!=len(spent)
            or {s['item_key'] for s in spent}!={r['entry_id'] for r in job['executions']}):
        raise ValueError('roster_gate_spent_unknown_or_executed_attempt_omitted')
    # Preserve failures for submitted, active and eliminated candidates too.
    # Only candidate admission is conditioned on successful development runs.
    records={};results={};items={};reviews=[];approval_digests=set();run_ids=set();task_ids=set();sources={}
    for reference in job['executions']:
        filename=_name(reference['intent_digest']);item=required[reference['item_id']]
        evaluation=read_owned(Path(evaluation_directory)/filename,uid=21004,gid=21004,limit=16777216)
        review=read_owned(Path(task_review_directory)/filename,uid=21005,gid=21001,limit=262144)
        record=execution_record(evaluation['run_request'],evaluation['result'],
                                evaluation['evidence_index'],evaluation['task_binding'])
        result=evaluation['result'];body=result['body']
        if (evaluation.get('kind')!='FormalTaskEvaluation' or evaluation.get('evaluator_uid')!=21004
                or evaluation['intent_digest']!=reference['intent_digest']
                or evaluation['deployment_epoch']!=bindings['deployment_epoch']
                or evaluation['trust_revision']!=bindings['trust_revision']
                or evaluation['run_request']['body']['config_digest']!=config_digest
                or record!=evaluation['execution_record']
                or review.get('kind')!='FormalTaskEvidenceReview' or review.get('gate_uid')!=21005
                or review.get('evidence_complete') is not True
                or review['evaluation_digest']!=evaluation['digest']
                or review['execution_record_digest']!=record['digest']
                or review['entry_digest']!=evaluation['entry_digest']
                or review['entry_digest']!=reference['entry_digest']
                or review['intent_digest']!=reference['intent_digest']
                or review['runtime_capture_digest']!=evaluation['runtime_capture_digest']
                or review['authority_snapshot_digest']!=evaluation['authority_snapshot_digest']
                or any(body[k]!=item[k] for k in ('subject_digest','case_digest','repetition_index'))
                or evaluation['evidence_index']['body']['complete'] is not True
                or body['coverage_complete'] is not True
                or body['run_id'] in run_ids or body['task_instance_id'] in task_ids):
            raise ValueError('roster_gate_actual_complete_task_chain')
        run_ids.add(body['run_id']);task_ids.add(body['task_instance_id'])
        previous=sources.setdefault(body['subject_digest'],evaluation['source_snapshot_digest'])
        if previous!=evaluation['source_snapshot_digest']:
            raise ValueError('roster_gate_same_subject_source_changed')
        approval_digests.add(evaluation['approval_digest']);reviews.append(review['digest'])
        records[record['digest']]=record;results[result['digest']]=result
        items[item['item_id']]=record['digest']
    if set(job['approval_digests'])!=approval_digests or len(job['approval_digests'])!=len(approval_digests):
        raise ValueError('roster_gate_actual_approval_set')
    applications=[];parent=bindings['subjects']['submitted']
    for number,pin in enumerate(job['applications'],1):
        application=read_owned(Path(application_directory)/_name(pin['assignment_digest']),uid=21005,gid=21001,limit=262144)
        if (application['digest']!=pin['review_digest'] or application.get('kind')!='GateBoundedCandidateApplication'
                or application.get('assignment_digest')!=pin['assignment_digest']
                or application.get('campaign_id')!=bindings['campaign']
                or application.get('deployment_epoch')!=bindings['deployment_epoch']
                or application.get('config_digest')!=config_digest
                or application.get('application_verified') is not True
                or application.get('repair_round')!=number
                or application.get('parent_subject_digest')!=parent):
            raise ValueError('roster_gate_actual_bounded_repair_chain')
        parent=application['candidate_bundle_digest'];applications.append(application)
    known={*bindings['subjects'].values(),*(a['candidate_bundle_digest'] for a in applications)}
    if {i['subject_digest'] for i in required.values()}!=known:
        raise ValueError('roster_gate_unaccounted_or_unpaired_subject')
    nominee=job['finalist']
    if nominee is not None and nominee not in {a['candidate_bundle_digest'] for a in applications}:
        raise ValueError('roster_gate_unapplied_finalist')
    # The current suite includes every discovered history case. Final roles
    # require every current case, even if an earlier eliminated candidate did
    # not yet know that case when its original plan was frozen.
    final_subjects={**bindings['subjects']}
    final_subjects.pop('finalist',None)
    if nominee is not None:final_subjects['finalist']=nominee
    reductions={};manifests={}
    for subject in sorted(known):
        subject_items=[i for i in required.values() if i['subject_digest']==subject]
        if subject in final_subjects.values():
            expected={(case['digest'],rep) for case in compiled['cases'].values()
                      for rep in range(case['body']['repetitions'])}
            if {(i['case_digest'],i['repetition_index']) for i in subject_items}!=expected:
                raise ValueError('roster_gate_final_subject_full_pairing_required')
        manifest=make_envelope('RequiredRunManifest',{'subject_digest':subject,'plan_digest':plan['digest'],
            'entries':[{'item_id':i['item_id'],'run_record_digests':[items[i['item_id']]]} for i in subject_items]})
        validate_required_run_manifest(manifest,plan,records,results);manifests[subject]=manifest
        reduced=[]
        for case in compiled['cases'].values():
            selected=[results[records[items[i['item_id']]]['body']['result_digest']]
                      for i in subject_items if i['case_digest']==case['digest']]
            if selected:reduced.append(reduce_case(selected,case))
        reductions[subject]=reduced
    if nominee is not None and any(c['body']['security_status']!='pass' or c['body']['utility_status']!='pass'
            or c['body']['completed_repetitions']!=3 for c in reductions[nominee]):
        raise ValueError('roster_gate_finalist_development_failed')
    scans={}
    for pin in job['scans']:
        if set(pin) not in ({'subject_digest','package_digest','receipt_digest','review_digest'},
                {'subject_digest','package_digest','receipt_digest','review_digest','semantic_directory'}):
            raise ValueError('roster_gate_scan_reference')
        subject=pin['subject_digest'];folder=Path(scan_directory)/_name(pin['receipt_digest'])[:-5]
        receipt=read_owned(folder/'scan-evidence.json',uid=21001,gid=21001,limit=262144)
        # The Gate output pathname is frozen before the review, so it uses the
        # known operation identity rather than its not-yet-produced result hash.
        scan_review=read_owned(Path(scan_review_directory)/_name(digest_jcs(receipt['operation_id'])),
                               uid=21005,gid=21001,limit=262144)
        snapshot=read_owned(folder/'source-snapshot.json',uid=21001,gid=21001,limit=262144)
        validate_envelope(snapshot)
        raw=_raw(folder/'raw-report.json',33554432)
        report,findings,_=reduce_scan(scope['profile'],raw,receipt['upstream_exit_code'],
            subject_digest=pin['package_digest'],require_llm='semantic_directory' not in pin,allow_risk_exit=True)
        if (subject not in final_subjects.values() or subject in scans
                or receipt['digest']!=pin['receipt_digest'] or receipt.get('kind')!='FormalScanEvidence'
                or snapshot['kind']!='SourceSnapshot' or snapshot['digest']!=sources[subject]
                or receipt['source_snapshot_digest']!=snapshot['digest']
                or pin['package_digest']!=snapshot['body']['skill_digest']
                or receipt['profile_id']!=scope['profile']
                or receipt['raw_report_digest']!=digest_bytes(raw)
                or scan_review['digest']!=pin['review_digest']
                or scan_review.get('kind')!='ScanEvidenceReview'
                or scan_review.get('evidence_complete') is not True
                or scan_review['export_receipt_digest']!=receipt['digest']
                or scan_review['raw_report_digest']!=digest_bytes(raw)
                or scan_review['deployment_digest']!=receipt['deployment_digest']
                or report['body']['status']!='complete'):
            raise ValueError('roster_gate_real_semantic_scan_incomplete')
        semantic_digest=None
        if 'semantic_directory' in pin:
            from skillloop.discovery.semantic_review import review_semantic
            report,findings,semantic_digest=review_semantic(pin['semantic_directory'],snapshot=snapshot,profile=scope['profile'],whole=whole)
        if subject==nominee:
            application=next(a for a in applications if a['candidate_bundle_digest']==subject)
            if pin['package_digest']!=application['package_digest']:
                raise ValueError('roster_gate_candidate_scanned_package_changed')
            if any(f['body']['severity'].lower() in {'high','critical'} for f in findings):
                raise ValueError('roster_gate_finalist_unresolved_high_finding')
        scans[subject]={'scanner_report':report,'findings':findings,'review_digest':scan_review['digest'],
            'semantic_evidence_digest':semantic_digest}
    if set(scans)!=set(final_subjects.values()):raise ValueError('roster_gate_final_subject_scan_missing')
    with current_authority(authority_directory,epoch=bindings['deployment_epoch'],
            config_digest=config_digest,trust_revision=bindings['trust_revision'],approval_digests=job['approval_digests']) as authority:
        heads=[h for h in authority.get('plan_heads',[]) if h['campaign_id']==bindings['campaign']]
        if len(heads)!=1 or heads[0]['plan_digest']!=plan['digest']:
            raise ValueError('roster_gate_actual_proxy_plan_head_changed')
        if datetime.now(timezone.utc)>=deadline:raise TimeoutError('roster_gate_original_clock_exhausted')
        evidence=_write(Path(output_directory),'development-evidence.json',{
            'kind':'FormalDevelopmentRosterEvidence','assignment_digest':job['digest'],
            'plan_digest':plan['digest'],'whole_round_manifest_digest':whole['digest'],
            'required_run_manifests':manifests,'case_reductions':reductions,
            'task_review_digests':reviews,'applications':applications,'scans':scans,
            'subjects':final_subjects,'qualification_issued':False})
        return _write(Path(output_directory),'freeze.json',{'kind':'FrozenCampaignSubjectRoster',
            'campaign_id':bindings['campaign'],'generation':bindings['generation'],
            'deployment_epoch':bindings['deployment_epoch'],'config_digest':config_digest,
            'source_snapshot_digest':bindings['source_snapshot_digest'],'trust_revision':bindings['trust_revision'],
            'subjects':final_subjects,'development_plan_digest':plan['digest'],
            'development_evidence_digest':evidence['digest'],'repair_rounds_allowed':job['repair_rounds_allowed'],
            'repair_rounds_used':len(applications),'protected_evaluation':'not_started','deadline':job['deadline']})


def main():
    os.umask(0o077)
    freeze_roster(assignment_path='/assignment/job.json',whole_round_manifest_path='/whole-round/manifest.json',
        evaluation_directory='/evaluation',task_review_directory='/task-reviews',application_directory='/applications',
        scan_directory='/scans',scan_review_directory='/scan-reviews',authority_directory='/authority-projection',
        output_directory='/roster')


if __name__=='__main__':main()
