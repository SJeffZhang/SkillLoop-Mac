"""Gate-owned archive withdrawal; no raw private evidence crosses to Controller."""
from datetime import datetime,timezone
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import digest_jcs
from skillloop.ci.qualification_store import QualificationIssuer


def withdraw():
    if os.geteuid()!=21005:raise PermissionError('qualification_withdrawal_gate_uid')
    job=read_owned('/assignment/job.json',uid=21001,gid=21005,limit=262144)
    fields={'kind','bindings','whole_round_manifest_digest','deadline','digest'}
    if set(job)!=fields or job['kind']!='FormalQualificationWithdrawalAssignment':
        raise ValueError('qualification_withdrawal_assignment')
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
        raise TimeoutError('qualification_withdrawal_original_clock')
    # Never manufacture an empty issuer or vault to represent withdrawal.
    for path in ('/eligibility/qualification.sqlite','/private-result/proofs.sqlite'):
        if not Path(path).is_file():raise ValueError('qualification_withdrawal_original_store_missing')
    bindings=job['bindings']
    issuer=QualificationIssuer('/eligibility/qualification.sqlite',
        deployment_epoch=bindings['deployment_epoch'],config_digest=bindings['config_digest'],
        authority_directory='/authority-projection',private_path='/private-result/proofs.sqlite')
    receipt=issuer.revoke(bindings['campaign'],expected_generation=bindings['generation'],expected_bindings=bindings)
    spending=read_owned('/assignment/spending.json',uid=21001,gid=21005,limit=8388608)
    if spending.get('kind')!='CampaignGateSpendingSnapshot' or spending.get('assignment_digest')!=job['digest']:
        raise ValueError('qualification_withdrawal_original_spending')
    costs=[c for c in spending['state']['auxiliary_executions']
        if c['operation_key']=='qualification-withdraw-'+job['digest'][7:]
        and c['stage']=='resource_archive_restore']
    if len(costs)!=1:raise ValueError('qualification_withdrawal_original_cost_missing')
    cost=costs[0]['requested_cost']
    from skillloop.ci.qualification_archive import preserve_withdrawn_issuer
    snapshot=preserve_withdrawn_issuer(issuer,receipt,assignment_digest=job['digest'],
        deadline=job['deadline'],maximum_bytes=cost['disk_bytes'],
        timeout_seconds=min(120,max(1,cost['seconds']-60)))
    result={'kind':'FormalQualificationWithdrawalCompletion','assignment_digest':job['digest'],
        'withdrawal':receipt,'issuer_snapshot_digest':snapshot['digest'],'qualification_revoked':True,'deletion_authorized':False}
    result['digest']=digest_jcs(result)
    output=_directory('/public-result',21005,21001,0o750)
    target=output/'withdrawal.json'
    if target.exists():
        if read_owned(target,uid=21005,gid=21001,limit=262144)!=result:
            raise ValueError('qualification_withdrawal_original_completion_conflict')
    else:_publish(target,result,21001)
    return result


if __name__=='__main__':
    os.umask(0o077)
    withdraw()
