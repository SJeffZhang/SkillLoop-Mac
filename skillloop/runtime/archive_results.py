"""Gate-owned public archive and restore result production.

Archive authorization and final API4 results are separate so the Proxy can
release its original reservation between two independently checked facts.
"""
from datetime import datetime,timezone
import os
from pathlib import Path

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import digest_jcs
from skillloop.proxy.wire import make_control,validate_control


def _read(path,uid,gid,limit=262144):
    return read_owned(path,uid=uid,gid=gid,limit=limit)


def run():
    if os.geteuid()!=21005:raise PermissionError('archive_result_actual_gate')
    job=_read('/assignment/job.json',21001,21005,2097152)
    fields={'kind','action','campaign','deployment_epoch','deadline','archive_manifest_path',
        'encrypted_review_path','coverage_path','qualification_withdrawal_path','issuer_snapshot_path',
        'registry_snapshot_path','resource_snapshot_path','release_authorization_path',
        'resource_release_path','restore_completion_path','new_deployment_epoch','digest'}
    if (set(job)!=fields or job['kind']!='FrozenArchiveResultAssignment'
            or job['action'] not in {'authorize_release','archive_result','restore_result'}
            or job['digest']!=digest_jcs({k:v for k,v in job.items() if k!='digest'})):
        raise ValueError('archive_result_frozen_assignment')
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
        raise TimeoutError('archive_result_original_clock')
    manifest=_read(job['archive_manifest_path'],21005,21001);validate_control(manifest)
    if (manifest['kind']!='ArchiveManifest' or manifest['body']['campaign_public_ref']!=job['campaign']
            or manifest['body']['source_deployment_epoch']!=job['deployment_epoch']):
        raise ValueError('archive_result_original_manifest')
    if job['action']=='restore_result':
        restored=_read(job['restore_completion_path'],21005,21001)
        archive=_read(job['release_authorization_path'],21005,21001)
        validate_control(archive)
        if (archive['kind']!='ArchiveResult' or archive['body']['archive_manifest_digest']!=manifest['digest']
                or archive['body']['qualification_withdrawn'] is not True
                or restored.get('kind')!='OpaqueEncryptedEvidenceRestoreCompletion'
                or restored.get('encrypted_bundle_digest')!=manifest['body']['encrypted_bundle_digest']
                or restored.get('new_deployment_epoch')!=job['new_deployment_epoch']
                or restored.get('old_credentials_activated') is not False
                or restored.get('campaign_coverage_complete') is not True
                or job['new_deployment_epoch']==job['deployment_epoch']):
            raise ValueError('restore_result_inert_new_epoch_chain')
        result=make_control('RestoreResult',{'archive_manifest_digest':manifest['digest'],
            'new_deployment_epoch':job['new_deployment_epoch'],'old_credentials_invalidated':True,
            'old_attestations_invalidated':True,'requires_full_reevaluation':True})
    else:
        review=_read(job['encrypted_review_path'],21005,21005)
        coverage=_read(job['coverage_path'],21005,21005,2097152)
        withdrawal=_read(job['qualification_withdrawal_path'],21005,21001)
        issuer=_read(job['issuer_snapshot_path'],21005,21005,2097152)
        registry=_read(job['registry_snapshot_path'],21001,21005,2097152)
        resource=_read(job['resource_snapshot_path'],21003,21005,2097152)
        gate_withdrawal=withdrawal.get('withdrawal',{})
        if (review.get('kind')!='IndependentEncryptedEvidenceReview'
                or review.get('encrypted_bundle_digest')!=manifest['body']['encrypted_bundle_digest']
                or review.get('campaign_coverage_complete') is not True
                or coverage.get('kind')!='IndependentCampaignArchiveCoverage'
                or coverage.get('digest')!=review.get('campaign_coverage_review_digest')
                or coverage.get('campaign')!=job['campaign']
                or coverage.get('resource_ownership_snapshot_digest')!=resource.get('digest')
                or withdrawal.get('kind')!='FormalQualificationWithdrawalCompletion'
                or withdrawal.get('qualification_revoked') is not True
                or gate_withdrawal.get('bindings',{}).get('campaign')!=job['campaign']
                or gate_withdrawal.get('qualification_revoked') is not True
                or issuer.get('kind')!='GateWithdrawnQualificationSnapshot'
                or issuer.get('campaign')!=job['campaign']
                or issuer.get('withdrawal_digest')!=gate_withdrawal.get('digest')
                or issuer.get('qualification_revoked') is not True
                or registry.get('kind')!='ControllerWithdrawnRegistrySnapshot'
                or registry.get('campaign')!=job['campaign']
                or registry.get('withdrawal',{}).get('gate_withdrawal_digest')!=gate_withdrawal.get('digest')
                or registry.get('campaign_dispatch_closed') is not True
                or resource.get('campaign')!=job['campaign']
                or resource.get('resource_release_completed') is not False):
            raise ValueError('archive_result_complete_withdrawn_review_chain')
        if job['action']=='authorize_release':
            result={'kind':'GateCampaignResourceReleaseAuthorization','campaign':job['campaign'],
                'deployment_epoch':job['deployment_epoch'],'resource_snapshot_digest':resource['digest'],
                'archive_manifest_digest':manifest['digest'],'independent_review_digest':review['digest'],
                'qualification_withdrawal_digest':gate_withdrawal['digest'],
                'registry_snapshot_digest':registry['digest'],'campaign_coverage_complete':True,
                'qualification_and_registry_withdrawn':True,'deletion_authorized':False}
            result['digest']=digest_jcs(result)
        else:
            authorization=_read(job['release_authorization_path'],21005,21001)
            released=_read(job['resource_release_path'],21003,21005)
            if (authorization.get('kind')!='GateCampaignResourceReleaseAuthorization'
                    or authorization.get('resource_snapshot_digest')!=resource['digest']
                    or authorization.get('archive_manifest_digest')!=manifest['digest']
                    or released.get('kind')!='ProxyCampaignResourceRelease'
                    or released.get('authorization_digest')!=authorization.get('digest')
                    or released.get('archive_manifest_digest')!=manifest['digest']
                    or released.get('reservation_state')!='released'
                    or released.get('physical_database_preserved') is not True
                    or released.get('local_inactive_removed') is not False):
                raise ValueError('archive_result_actual_resource_release')
            result=make_control('ArchiveResult',{'archive_manifest_digest':manifest['digest'],
                'qualification_withdrawn':True,'local_inactive_removed':False})
    output=_directory('/public-result',21005,21001,0o750)
    target=output/'result.json'
    if target.exists():
        if _read(target,21005,21001)!=result:raise ValueError('archive_result_original_conflict')
    else:_publish(target,result,21001)
    return result


if __name__=='__main__':
    os.umask(0o077);run()
