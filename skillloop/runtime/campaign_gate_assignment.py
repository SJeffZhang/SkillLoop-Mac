"""Controller prepares the final Gate from current opaque Factory provenance.

No private plan, future case, original output or result matrix enters this
caller. The Gate resolves those under its own private authority permissions.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import re,time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory,_publish


def produce_campaign_gate_assignment(*,policy_path,assignment_directory,campaign,whole,registry,ledger):
    if os.geteuid()!=21001:raise PermissionError('campaign_gate_assignment_actual_controller')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=262144)
    fields={'kind','campaign_digest','deployment_epoch','whole_round_manifest_digest','factory_commit_path','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenCampaignGateProduction'
            or policy['campaign_digest']!=campaign or policy['deployment_epoch']!=whole['deployment_epoch']
            or policy['whole_round_manifest_digest']!=whole['digest']
            or campaign not in {c['campaign_digest'] for c in whole['campaigns']}
            or type(policy['factory_commit_path']) is not str
            or not Path(policy['factory_commit_path']).is_absolute()
            or '..' in Path(policy['factory_commit_path']).parts):
        raise ValueError('campaign_gate_assignment_original_recipe')
    factory=read_owned(policy['factory_commit_path'],uid=21004,gid=21001,limit=262144)
    if (set(factory)!={'kind','campaign_public_ref','opaque_ref','aggregate_status','digest'}
            or factory['kind']!='FormalPrivateFactoryCommit' or factory['campaign_public_ref']!=campaign
            or factory['aggregate_status']!='sealed' or type(factory['opaque_ref']) is not str
            or not re.fullmatch(r'protected-[0-9a-f]{32}',factory['opaque_ref'])):
        raise ValueError('campaign_gate_assignment_actual_factory_projection')
    from skillloop.runtime.round_manifest import validate_round_manifest
    validate_round_manifest(whole)
    root=_directory(assignment_directory,21001,21005,0o750)
    with registry.private_scope(campaign=campaign) as state:
        job={'kind':'FormalCampaignGateAssignment','bindings':state['bindings'],
            'opaque_ref':factory['opaque_ref'],'whole_round_manifest_digest':whole['digest'],
            'deadline':state['gate_freeze']['deadline']}
        job['digest']=digest_jcs(job)
        deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
        if (deadline.tzinfo is None or ledger.campaign_started_at is None
                or deadline.timestamp()!=ledger.campaign_started_at+28800):
            raise ValueError('campaign_gate_assignment_original_campaign_clock')
        if os.path.lexists(root/'production.json'):
            receipt=read_owned(root/'production.json',uid=21001,gid=21005,limit=262144)
            original=read_owned(root/'job.json',uid=21001,gid=21005,limit=262144)
            if (receipt.get('kind')!='ControllerCampaignGateAssignmentProduced'
                    or receipt['policy_digest']!=policy['digest'] or receipt['factory_commit_digest']!=factory['digest']
                    or receipt['assignment_digest']!=job['digest'] or original!=job
                    or receipt['budget_closure']!='within_original_budget'):
                raise ValueError('campaign_gate_assignment_original_publication_conflict')
            return receipt
        if any(root.iterdir()):raise RuntimeError('campaign_gate_assignment_partial_publication_unknown')
        began=time.monotonic();deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=30:
            raise TimeoutError('campaign_gate_assignment_original_budget')
        cost=ledger.consume_auxiliary(manifest=whole,campaign=campaign,stage='gate_qualification_report',
            operation_key='campaign-gate-assignment-'+policy['digest'][7:],seconds=30,
            input_tokens=0,output_tokens=0,disk_bytes=1048576)
        _publish(root/'job.json',job,21005)
        elapsed=time.monotonic()-began
        within=elapsed<=30 and datetime.now(timezone.utc)<deadline
        receipt={'kind':'ControllerCampaignGateAssignmentProduced','policy_digest':policy['digest'],
            'factory_commit_digest':factory['digest'],'assignment_digest':job['digest'],
            'spending':cost,'elapsed_seconds':elapsed,
            'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure',
            'qualification_issued':False}
        receipt['digest']=digest_jcs(receipt);_publish(root/'production.json',receipt,21005)
        if not within:raise TimeoutError('campaign_gate_assignment_original_budget_expired')
        return receipt
