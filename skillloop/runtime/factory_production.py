"""Controller derives a Factory delegation from current public Gate evidence."""
from datetime import datetime, timezone
from pathlib import Path
import os
import re
import time
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory, _publish
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.protected_flow import _controller_record
from skillloop.runtime.private_session_dispatch import resolve_session_keeper


def produce_factory_dispatch(*,recipe,assignment_directory,gate_freeze_path,journal_directory,whole,registry,ledger):
    if os.geteuid()!=21001:raise PermissionError('factory_production_actual_controller')
    fields={'kind','factory_profile_digest','roster_assignment_path','roster_evidence_path','dispatch_template','digest'}
    dispatch_fields={'kind','campaign_digest','image','whole_round_manifest_digest',
        'campaign_deadline','timeout_seconds','maximum_evidence_bytes','keeper_id','mounts'}
    if (set(recipe)!=fields or recipe['kind']!='FrozenPrivateFactoryProduction'
            or recipe['digest']!=digest_jcs({k:v for k,v in recipe.items() if k!='digest'})
            or type(recipe['dispatch_template']) is not dict
            or set(recipe['dispatch_template']) not in (dispatch_fields,(dispatch_fields-{'keeper_id'})|{'keeper_reference'})
            or recipe['dispatch_template']['kind']!='FrozenPrivateFactoryDispatch'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',recipe['factory_profile_digest'])):
        raise ValueError('factory_production_frozen_recipe')
    template=resolve_session_keeper(recipe['dispatch_template'],deployment_epoch=whole['deployment_epoch'])
    original=read_owned(recipe['roster_assignment_path'],uid=21001,gid=21005,limit=8388608)
    evidence=read_owned(recipe['roster_evidence_path'],uid=21005,gid=21001,limit=16777216)
    freeze=read_owned(gate_freeze_path,uid=21005,gid=21001,limit=262144)
    with registry.private_scope(campaign=template['campaign_digest']) as state:
        if (original.get('kind')!='FormalDevelopmentRosterAssignment'
                or evidence.get('kind')!='FormalDevelopmentRosterEvidence'
                or freeze!=state['gate_freeze']
                or evidence.get('assignment_digest')!=original['digest']
                or evidence.get('digest')!=freeze['development_evidence_digest']
                or evidence.get('subjects')!=freeze['subjects']
                or evidence.get('plan_digest')!=original['plan']['digest']
                or original['plan']['digest']!=freeze['development_plan_digest']
                or digest_jcs(original['config'])!=freeze['config_digest']
                or {k:v for k,v in original['bindings'].items() if k!='subjects'}!={k:v for k,v in state['bindings'].items() if k!='subjects'}
                or any(original['bindings']['subjects'].get(role)!=state['bindings']['subjects'].get(role) for role in ('submitted','active'))
                or template['whole_round_manifest_digest']!=whole['digest']
                or original['whole_round_manifest_digest']!=whole['digest']
                or template['image']!=whole['image']
                or template['campaign_deadline']!=freeze['deadline']):
            raise ValueError('factory_production_current_gate_and_registry')
        job={'kind':'FormalPrivateFactoryAssignment','campaign_id':freeze['campaign_id'],
            'config':original['config'],'whole_round_manifest_digest':whole['digest'],
            'gate_freeze_path':'/roster/freeze.json','gate_freeze_digest':freeze['digest'],
            'development':original['development'],'development_plan':original['plan'],
            'factory_profile_digest':recipe['factory_profile_digest'],
            'approval_digests':original['approval_digests'],'trust_revision':freeze['trust_revision'],
            'deadline':freeze['deadline']}
    job['digest']=digest_jcs(job)
    root=_directory(journal_directory,21001,21001,0o700)
    assignment=_directory(assignment_directory,21001,21004,0o750)
    target=assignment/'job.json';receipt=root/'production.json';cost_path=root/'production-cost.json'
    requested={'seconds':30,'input_tokens':0,'output_tokens':0,'disk_bytes':1048576}
    if os.path.lexists(receipt):
        saved=_controller_record(receipt);cost=_controller_record(cost_path)
        if (saved.get('kind')!='ControllerPrivateFactoryProduced' or saved['recipe_digest']!=recipe['digest']
                or saved['job_digest']!=job['digest'] or cost.get('kind')!='ControllerPrivateFactoryProductionCost'
                or cost['spending']['requested_cost']!=requested
                or cost['spending']['operation_key']!='factory-production-'+recipe['digest'][7:]
                or read_owned(target,uid=21001,gid=21004,limit=8388608)!=job):
            raise ValueError('factory_production_original_receipt_changed')
        if saved.get('budget_closure')!='within_original_budget':
            raise TimeoutError('factory_production_original_budget_expired')
    else:
        if any(assignment.iterdir()) or cost_path.exists() or (root/'dispatch-intent.json').exists():
            raise RuntimeError('factory_production_partial_original_preserved')
        campaign=next(c for c in whole['campaigns'] if c['campaign_digest']==template['campaign_digest'])
        bound=campaign['stages']['private_factory_lifecycle']
        spent=sum(row.get('stage')=='private_factory_lifecycle' for row in ledger.read().get('auxiliary_executions',[]))
        deadline=datetime.fromisoformat(template['campaign_deadline'].replace('Z','+00:00'))
        if (type(template['timeout_seconds']) is not int or not 1<=template['timeout_seconds']<=120
                or type(template['maximum_evidence_bytes']) is not int or not 1<=template['maximum_evidence_bytes']<=33554432
                or bound['count']-spent<2 or bound['seconds']<max(30,template['timeout_seconds']+60)
                or bound['disk_bytes']<max(1048576,template['maximum_evidence_bytes'])
                or deadline.tzinfo is None or ledger.campaign_started_at is None
                or deadline.timestamp()!=ledger.campaign_started_at+28800
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=2*bound['seconds']+120):
            raise ValueError('factory_production_complete_original_cost')
        began=time.monotonic()
        cost=ledger.consume_auxiliary(manifest=whole,campaign=template['campaign_digest'],
            stage='private_factory_lifecycle',operation_key='factory-production-'+recipe['digest'][7:],**requested)
        _save(root,'production-cost.json',{'kind':'ControllerPrivateFactoryProductionCost','spending':cost})
        _publish(target,job,21004)
        within=time.monotonic()-began<=30 and datetime.now(timezone.utc)<deadline
        _save(root,'production.json',{'kind':'ControllerPrivateFactoryProduced','recipe_digest':recipe['digest'],
            'job_digest':job['digest'],'freeze_digest':freeze['digest'],'qualification_issued':False,
            'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure'})
        if not within:raise TimeoutError('factory_production_original_budget_expired')
    result={**template,'assignment_digest':job['digest']};result['digest']=digest_jcs(result)
    return result
