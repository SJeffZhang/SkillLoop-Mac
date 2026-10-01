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


def verify_protected_entry(entry, *, image, source_digest, model_port):
    """Private controller-only entry. Agents receive only their current request."""
    import base64
    from skillloop.protocol import digest_bytes
    if entry.get('digest')!=digest_jcs({k:v for k,v in entry.items() if k!='digest'}):raise ValueError('protected_entry_digest')
    config=entry['config'];compiled=entry['compiled'];plan=entry['plan']
    if entry.get('kind')!='protected' or entry['role'] not in {'submitted','finalist'}:raise ValueError('protected_subject_role')
    if config['mac_runtime_image']!=image or entry['source_index_digest']!=source_digest:raise ValueError('protected_source_identity')
    if config['model_service_port']!=model_port:raise ValueError('protected_model_service_binding')
    if config['deployment_epoch']==entry['development_epoch'] or not entry['model_lifecycle_digest'] or not entry['approval_factory_digest']:raise ValueError('protected_lifecycle')
    if compiled['profile_id']!=entry['profile'] or compiled['suite']['body']['visibility']!='private_evaluation' or compiled['suite']['body']['epoch_id']!=entry['epoch_id']:raise ValueError('protected_suite_binding')
    case=compiled['cases'][entry['case_id']]
    if case['body']['split']!='protected':raise ValueError('protected_case_required')
    inputs={k:base64.b64decode(v,validate=True) for k,v in entry['private_inputs'].items()}
    fixture=digest_jcs({'inputs':{k:digest_bytes(v) for k,v in inputs.items()},'expected':entry['private_expected_digest']})
    if fixture!=case['body']['fixture_digest']:raise ValueError('private_fixture_binding')
    validate_plan(plan,compiled['suite'])
    if plan['body']['phase']!='protected' or plan['body']['config_digest']!=digest_jcs(config) or plan['body']['campaign_id']!=entry['campaign_id']:raise ValueError('protected_plan_config')
    matching=[i for i in plan['body']['items'] if i['subject_digest']==compiled['subject_digest'] and i['case_digest']==case['digest'] and i['repetition_index']==entry['repetition'] and i['subject_role']==entry['role']]
    if len(matching)!=1 or matching[0]['phase']!='protected' or matching[0]['requirement']!='required':raise ValueError('protected_run_not_reserved')
    return entry


def protected_options(entry):
    import base64
    return {'inputs_override':{k:base64.b64decode(v,validate=True) for k,v in entry['private_inputs'].items()},'approval_factory_digest':entry['approval_factory_digest']}
