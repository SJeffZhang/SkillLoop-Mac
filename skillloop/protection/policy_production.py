"""Admin derives current-task source policy from the actual frozen Gate roster.

This contains approved public packages, never private cases or future results.
The Evaluator separately checks the live Proxy catalog before delivery.
"""
from datetime import datetime, timezone
import base64
import os
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.families.registry import FamilyRegistry
from skillloop.loader import ApprovedPackageLoader, validate_source_admission
from skillloop.protocol import digest_jcs, validate_envelope
from skillloop.protection.current_task import _directory, _publish


def produce_current_policy(assignment_path):
    if os.geteuid() != 21010 or not {21001, 21003, 21004} <= set(os.getgroups()) | {os.getegid()}:
        raise PermissionError('private_policy_actual_admin_custody')
    job = read_owned(assignment_path, uid=21001, gid=21010, limit=2097152)
    fields = {'kind', 'campaign_id', 'deployment_epoch', 'config', 'roster_path',
              'source_grant_paths', 'domain', 'subject_policies', 'profile_id', 'output_directory', 'digest'}
    if set(job) != fields or job['kind'] != 'AdminPrivateCurrentPolicyProduction':
        raise ValueError('private_policy_production_assignment')
    roster = read_owned(job['roster_path'], uid=21005, gid=21001, limit=262144)
    config = job['config']
    if (roster.get('kind') != 'FrozenCampaignSubjectRoster'
            or roster.get('protected_evaluation') != 'not_started'
            or roster.get('campaign_id') != job['campaign_id']
            or roster.get('deployment_epoch') != job['deployment_epoch']
            or roster.get('config_digest') != digest_jcs(config)
            or config.get('whole_flow_required') is not True
            or config.get('deployment_epoch') != job['deployment_epoch']
            or config.get('source_admission_authority') != 'admin_campaign_catalog_v1'):
        raise ValueError('private_policy_original_frozen_roster')
    deadline = datetime.fromisoformat(roster['deadline'].replace('Z', '+00:00'))
    if deadline.tzinfo is None or deadline <= datetime.now(timezone.utc):
        raise TimeoutError('private_policy_original_clock')
    subjects = roster['subjects']
    if (type(subjects) is not dict or 'submitted' not in subjects
            or set(subjects) - {'submitted', 'finalist', 'active'}
            or type(job['source_grant_paths']) is not list
            or not 1 <= len(job['source_grant_paths']) <= 4):
        raise ValueError('private_policy_complete_roster_sources')
    profile = job['profile_id']
    family = FamilyRegistry().profile(profile)['family_id']
    validate_envelope(job['domain'])
    if job['domain']['kind'] != 'AuthorizationDomain' or type(job['subject_policies']) is not dict or set(job['subject_policies']) != set(subjects.values()):
        raise ValueError('private_policy_complete_subject_policy_binding')
    from scripts.spec_v22_core import canonical_policy
    policies = {subject: canonical_policy(policy) for subject, policy in job['subject_policies'].items()}
    if any(policy['body']['domain_digest'] != job['domain']['digest'] for policy in policies.values()):
        raise ValueError('private_policy_actual_domain_binding')
    sources = {}
    for path in job['source_grant_paths']:
        grant = read_owned(path, uid=21010, gid=21003, limit=2097152)
        if (grant.get('kind') != 'AdminCampaignSourceAdmission'
                or grant.get('campaign_id') != job['campaign_id']
                or grant.get('deployment_epoch') != job['deployment_epoch']
                or grant.get('config') != config
                or grant.get('subject_digest') not in set(subjects.values())
                or grant['subject_digest'] in sources):
            raise ValueError('private_policy_current_source_grant')
        admission = grant['admission']
        validate_source_admission(admission, config, grant['subject_digest'])
        package = {name: base64.b64decode(raw, validate=True)
                   for name, raw in admission['package_files'].items()}
        selected = ApprovedPackageLoader(approved_sources=admission['approved_sources'],
            reference_resource_ids=admission['reference_resource_ids'],
            approved_subjects=admission.get('approved_subjects')).select(
                admission['source_snapshot'], package, admission['manifest'],
                profile_id=profile, family_id=family)
        if selected.subject_digest != grant['subject_digest']:
            raise ValueError('private_policy_actual_selected_subject')
        candidate = admission.get('approved_subjects', {}).get(selected.source_snapshot_digest)
        if candidate is None or candidate['body']['policy_digest'] != policies[selected.subject_digest]['digest']:
            raise ValueError('private_policy_actual_candidate_policy')
        sources[grant['subject_digest']] = admission
    if set(sources) != set(subjects.values()):
        raise ValueError('private_policy_required_subject_source_missing')
    value = {'kind': 'AdminPrivateCurrentTaskPolicyV2', 'campaign_id': job['campaign_id'],
        'deployment_epoch': job['deployment_epoch'], 'config_digest': digest_jcs(config),
        'domain': job['domain'], 'subject_policies': policies, 'sources': sources}
    value['digest'] = digest_jcs(value)
    output = _directory(job['output_directory'], 21010, 21004, 0o750)
    target = output / 'policy.json'
    # Original exact publication can be recovered; partial output cannot be
    # overwritten or treated as a reason to produce a different policy.
    if os.path.lexists(target):
        if read_owned(target, uid=21010, gid=21004, limit=8388608) != value:
            raise ValueError('private_policy_original_publication_conflict')
    else:
        if any(output.iterdir()):
            raise RuntimeError('private_policy_partial_publication_preserved')
        _publish(target, value, 21004)
    result = {'kind': 'AdminPrivateCurrentPolicyProduced', 'assignment_digest': job['digest'],
        'campaign_id': job['campaign_id'], 'deployment_epoch': job['deployment_epoch'],
        'roster_digest': roster['digest'], 'policy_digest': value['digest'],
        'proxy_admission_verified': False, 'qualification_issued': False}
    result['digest'] = digest_jcs(result)
    return result
