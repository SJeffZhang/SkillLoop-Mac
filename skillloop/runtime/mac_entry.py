"""Frozen entry admission before a trusted Mac controller starts a run."""
from skillloop.protocol import digest_jcs
from scripts.spec_v22_core import validate_plan

def verify_formal_entry(entry,*,image,source_digest,model_port):
    if entry.get('digest')!=digest_jcs({k:v for k,v in entry.items() if k!='digest'}):raise ValueError('formal_entry_digest')
    config=entry['config']
    if config['mac_runtime_image']!=image or entry['source_index_digest']!=source_digest:raise ValueError('formal_source_identity')
    if config['model_service_port']!=model_port:raise ValueError('formal_model_service_binding')
    compiled=entry['compiled'];plan=entry['plan'];role=entry['role']
    if role not in {'candidate','submitted'}:raise ValueError('formal_subject_role')
    if compiled['profile_id']!=entry['profile'] or entry['case_id'] not in compiled['cases']:raise ValueError('formal_case_binding')
    validate_plan(plan,compiled['suite'])
    if plan['body']['config_digest']!=digest_jcs(config) or plan['body']['campaign_id']!=entry['campaign_id']:raise ValueError('formal_plan_config')
    matching=[item for item in plan['body']['items'] if item['subject_digest']==compiled['subject_digest'] and item['case_digest']==compiled['cases'][entry['case_id']]['digest'] and item['repetition_index']==entry['repetition'] and item['subject_role']==role]
    if len(matching)!=1 or matching[0]['requirement']!='required':raise ValueError('formal_run_not_reserved')
    return entry
