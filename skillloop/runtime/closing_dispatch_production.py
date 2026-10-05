"""Produce one opaque Controller delegation for the current private task.

The Admin recipe fixes scope and mount policy before execution. Only the current
Evaluator reference enters the delegation; Controller never reads private cases.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.proposal_dispatch import _save


def closing_producer_template(recipe,*,stage,reference_path):
    fields={'kind','stage','production_policy_digest','current_reference_path','assignment_directory','dispatch_template','digest'}
    template_fields={'kind','image','campaign_deadline','campaign_digest','whole_round_manifest_digest',
        'maximum_evidence_bytes','timeout_seconds','keeper_id','mounts'}
    if (type(recipe) is not dict or set(recipe)!=fields
            or recipe.get('kind')!='FrozenPrivateClosingProducerProduction'
            or recipe['digest']!=digest_jcs({k:v for k,v in recipe.items() if k!='digest'})
            or recipe['stage']!=stage or recipe['current_reference_path']!=reference_path
            or type(recipe['dispatch_template']) is not dict
            or set(recipe['dispatch_template'])!=template_fields
            or recipe['dispatch_template']['kind']!='FrozenOpaquePrivateSessionDispatch'):
        raise ValueError('private_closing_delegation_frozen_recipe')
    from skillloop.protection.closing_actions import STAGES
    import re
    if (stage not in STAGES or not re.fullmatch(r'sha256:[0-9a-f]{64}',recipe['production_policy_digest'])
            or not Path(recipe['assignment_directory']).is_absolute()
            or '..' in Path(recipe['assignment_directory']).parts):
        raise ValueError('private_closing_delegation_recipe_identity')
    return recipe['dispatch_template']


def produce_closing_dispatch(*,recipe,stage,reference_path,whole,ledger,registry,journal_directory):
    if os.geteuid()!=21001:raise PermissionError('private_closing_delegation_actual_controller')
    from skillloop.runtime.protected_flow import _controller_record
    template=closing_producer_template(recipe,stage=stage,reference_path=reference_path)
    reference=read_owned(reference_path,uid=21004,gid=21001,limit=262144)
    if (reference.get('kind')!='EvaluatorOpaqueRunReference'
            or reference.get('campaign_id')!=template['campaign_digest']
            or reference.get('deployment_epoch')!=whole['deployment_epoch']
            or template['whole_round_manifest_digest']!=whole['digest'] or template['image']!=whole['image']):
        raise ValueError('private_closing_delegation_original_reference')
    job={'kind':'ControllerPrivateClosingActionProduction','policy_digest':recipe['production_policy_digest'],
        'reference_digest':reference['digest'],'stage':stage}
    job['digest']=digest_jcs(job)
    policy={**template,'action_digest':job['digest']};policy['digest']=digest_jcs(policy)
    root=_directory(journal_directory,21001,21001,0o700)
    assignment=_directory(recipe['assignment_directory'],21001,21004,0o750)
    filename=stage+'.production-policy.json';path=root/filename
    if os.path.lexists(path):
        previous=_controller_record(path)
        actual=read_owned(assignment/'action.json',uid=21001,gid=21004,limit=262144)
        if (previous.get('kind')!='PrivateClosingDelegationProduced'
                or previous.get('recipe_digest')!=recipe['digest']
                or previous.get('reference_digest')!=reference['digest'] or previous.get('policy')!=policy
                or previous.get('budget_closure')!='within_original_budget' or actual!=job):
            raise ValueError('private_closing_delegation_changed_original')
        return policy
    if any(assignment.iterdir()):raise RuntimeError('private_closing_delegation_partial_unknown_no_regeneration')
    deadline=datetime.fromisoformat(template['campaign_deadline'].replace('Z','+00:00'))
    if (deadline.tzinfo is None or ledger.campaign_started_at is None
            or deadline.timestamp()!=ledger.campaign_started_at+28800
            or (deadline-datetime.now(timezone.utc)).total_seconds()<=30):
        raise TimeoutError('private_closing_delegation_original_clock')
    with registry.private_scope(campaign=template['campaign_digest']) as state:
        if state['gate_freeze']['deadline']!=template['campaign_deadline']:
            raise ValueError('private_closing_delegation_current_registry')
        began=time.monotonic()
        cost=ledger.consume_auxiliary(manifest=whole,campaign=template['campaign_digest'],stage='protected',
            operation_key='private-closing-delegation-'+job['digest'][7:],seconds=30,
            input_tokens=0,output_tokens=0,disk_bytes=1048576)
        _save(root,stage+'.production-policy.cost.json',{'kind':'PrivateClosingDelegationSpending',
            'recipe_digest':recipe['digest'],'reference_digest':reference['digest'],'spending':cost})
        _publish(assignment/'action.json',job,21004)
        elapsed=time.monotonic()-began;within=elapsed<=30 and datetime.now(timezone.utc)<deadline
        _save(root,filename,{'kind':'PrivateClosingDelegationProduced','recipe_digest':recipe['digest'],
            'reference_digest':reference['digest'],'policy':policy,'spending':cost,
            'elapsed_seconds':elapsed,'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure',
            'qualification_issued':False})
        if not within:raise TimeoutError('private_closing_delegation_original_budget_expired')
    return policy
