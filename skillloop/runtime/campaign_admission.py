"""Register only an exact source already admitted by the real Proxy authority."""
import os
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs,validate_envelope
from skillloop.proxy.qualification_authority import current_authority
from skillloop.runtime.round_manifest import read_round_manifest


def register_campaign(*,registration_path,authority_directory,registry,ledger,whole_round_manifest_path,operation_id):
    if os.geteuid()!=21001:raise PermissionError('campaign_registration_actual_controller')
    job=read_owned(registration_path,uid=21010,gid=21001,limit=2097152)
    fields={'kind','project','profile','source','config_digest','deployment_epoch','trust_revision',
            'subjects','campaign_digest','approval_digests','digest'}
    if set(job)!=fields or job['kind']!='AdminFormalCampaignRegistration':
        raise ValueError('campaign_registration_frozen_shape')
    validate_envelope(job['source']);whole=read_round_manifest(whole_round_manifest_path)
    predicted=digest_jcs({'project':job['project'],'profile':job['profile'],
        'source_snapshot_digest':job['source']['digest'],'config_digest':job['config_digest'],
        'deployment_epoch':job['deployment_epoch'],'trust_revision':job['trust_revision'],
        'submitted_subject':job['subjects']['submitted']})
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==predicted),None)
    if (predicted!=job['campaign_digest'] or scope is None or scope['profile']!=job['profile']
            or whole['deployment_epoch']!=job['deployment_epoch'] or ledger.campaign_started_at is None):
        raise ValueError('campaign_registration_original_manifest_scope')
    with current_authority(authority_directory,epoch=job['deployment_epoch'],config_digest=job['config_digest'],
            trust_revision=job['trust_revision'],approval_digests=job['approval_digests'],campaign=predicted) as authority:
        admitted={s['subject_digest']:s for s in authority.get('source_admissions',[]) if s['campaign_id']==predicted}
        if any(subject not in admitted for subject in job['subjects'].values()):
            raise ValueError('campaign_registration_proxy_source_grant_missing')
        actual=admitted[job['subjects']['submitted']]
        if (actual['source_snapshot_digest']!=job['source']['digest']
                or actual['git_provenance'].get('package_bytes_verified') is not True
                or actual['git_provenance']['source_commit_sha']!=job['source']['body']['source_commit_sha']):
            raise ValueError('campaign_registration_actual_git_provenance')
        cost=ledger.consume_auxiliary(manifest=whole,campaign=predicted,stage='approval_deployment',
            operation_key='registry-'+job['digest'][7:],seconds=5,input_tokens=0,output_tokens=0,disk_bytes=262144)
        bindings=registry.begin_evaluation(project=job['project'],profile=job['profile'],source=job['source'],
            config_digest=job['config_digest'],deployment_epoch=job['deployment_epoch'],trust_revision=job['trust_revision'],
            subjects=job['subjects'],operation_id=operation_id,campaign_started_at=ledger.campaign_started_at)
        if bindings['campaign']!=predicted:raise ValueError('campaign_registration_identity_changed')
    result={'kind':'FormalCampaignRegistered','bindings':bindings,'registration_digest':job['digest'],
        'authority_projection_digest':authority['digest'],'spending':cost,'qualification_issued':False}
    result['digest']=digest_jcs(result);return result
