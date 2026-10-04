"""Admin produces append-only complete public development pairing revisions."""
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.discovery.suite import append_formal_dev_plan
from skillloop.protocol import digest_jcs,make_envelope,validate_envelope
from skillloop.protection.current_task import _directory,_publish
from scripts.spec_v22_core import validate_plan,validate_suite


def produce_plan_revision(assignment_path):
    if os.geteuid()!=21010 or 21003 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('plan_producer_actual_admin')
    job=read_owned(assignment_path,uid=21001,gid=21010,limit=8388608)
    fields={'kind','deployment_digest','deployment_epoch','campaign_id','config','parent_plan',
        'parent_suite','compiled','subjects','source_grant_paths','inbox_directory','reason','digest'}
    if set(job)!=fields or job['kind']!='AdminPublicPlanProduction':raise ValueError('plan_producer_assignment')
    parent,old_suite=job['parent_plan'],job['parent_suite'];validate_plan(parent,old_suite)
    compiled=job['compiled'];suite=compiled['suite']
    validate_suite(suite,list(compiled['cases'].values()),compiled['objectives'])
    if (parent['body']['campaign_id']!=job['campaign_id'] or parent['body']['config_digest']!=digest_jcs(job['config'])
            or parent['body']['phase']!='dev' or suite['body']['visibility']!='public_dev'
            or job['config'].get('deployment_epoch')!=job['deployment_epoch']
            or type(job['subjects']) is not dict or not job['subjects']
            or any(role not in {'submitted','candidate','finalist','active_baseline'} for role in job['subjects'])):
        raise ValueError('plan_producer_original_development_identity')
    original_subjects={i['subject_digest'] for i in parent['body']['items'] if i['requirement']=='required'}
    if not original_subjects.issubset(set(job['subjects'].values())):
        raise ValueError('plan_producer_original_subject_pair_omitted')
    cases={c['case_digest']:c for c in suite['body']['cases']}
    if any(cases.get(c['case_digest'])!=c for c in old_suite['body']['cases']):
        raise ValueError('plan_producer_old_case_semantics_changed')
    sources={}
    for path in job['source_grant_paths']:
        grant=read_owned(path,uid=21010,gid=21003,limit=2097152)
        if (grant.get('kind')!='AdminCampaignSourceAdmission' or grant.get('campaign_id')!=job['campaign_id']
                or grant.get('deployment_epoch')!=job['deployment_epoch'] or grant.get('config')!=job['config']):
            raise ValueError('plan_producer_current_source_grant')
        sources[grant['subject_digest']]=grant
    if any(subject not in sources for subject in job['subjects'].values()):
        raise ValueError('plan_producer_all_subject_sources_required')
    items=list(parent['body']['items'])
    # Generate every applicable repetition for every current subject. The
    # caller cannot select only favorable pairs or discard original rows.
    for role,subject in sorted(job['subjects'].items()):
        provisional=make_envelope('ExecutionPlan',{**parent['body'],'items':items,
            'suite_digest':suite['digest'],'reserved_rollouts':sum(i['attempts_reserved'] for i in items if i['requirement']=='required'),
            'reserved_execution_ms':sum(i['timeout_ms']*i['attempts_reserved'] for i in items if i['requirement']=='required')})
        plan=append_formal_dev_plan({**compiled,'subject_digest':subject},campaign_id=job['campaign_id'],
            config=job['config'],role=role,parent=provisional)
        items=plan['body']['items']
    body={**plan['body'],**job['config']['development_budget'],'revision':parent['body']['revision']+1,'parent_plan_digest':parent['digest']}
    plan=make_envelope('ExecutionPlan',body);validate_plan(plan,suite)
    if items==parent['body']['items']:raise ValueError('plan_producer_no_new_required_rows')
    grant={'kind':'AdminCampaignPlanRevision','deployment_digest':job['deployment_digest'],
        'deployment_epoch':job['deployment_epoch'],'campaign_id':job['campaign_id'],
        'parent_plan':parent,'parent_suite':old_suite,'plan':plan,'suite':suite,'reason':job['reason']}
    grant['digest']=digest_jcs(grant)
    inbox=_directory(job['inbox_directory'],21010,21003,0o750);target=inbox/(grant['digest'][7:]+'.json')
    if target.exists():
        if read_owned(target,uid=21010,gid=21003,limit=2097152)!=grant:raise ValueError('plan_producer_original_revision_conflict')
    else:_publish(target,grant,21003)
    result={'kind':'AdminPublicPlanProduced','assignment_digest':job['digest'],'plan_digest':plan['digest'],
        'revision_grant_digest':grant['digest'],'proxy_admission_verified':False,'original_budget_reset':False,
        'qualification_issued':False};result['digest']=digest_jcs(result);return result
