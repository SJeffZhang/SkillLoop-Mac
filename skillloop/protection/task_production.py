"""Evaluator selects one required private task by its non-secret ordinal."""
from datetime import datetime,timezone
from pathlib import Path
import os,time
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory,_publish,prepare_and_deliver,prepare_launch_reference


def produce_current_task(*,authority,job,private_directory,projection_directory,authority_directory):
    if os.geteuid()!=21004 or authority.readonly:
        raise PermissionError('private_task_production_actual_evaluator')
    policy=read_owned('/task-policy/policy.json',uid=21010,gid=21004,limit=262144)
    fields={'kind','campaign_id','deployment_epoch','config_digest','campaign_deadline','task_ordinal','maximum_wait_seconds','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenPrivateCurrentTaskProducerPolicy'
            or policy['digest']!=job['policy_digest'] or policy['task_ordinal']!=job['task_ordinal']
            or type(policy['task_ordinal']) is not int or not 0<=policy['task_ordinal']<128
            or type(policy['maximum_wait_seconds']) is not int or not 1<=policy['maximum_wait_seconds']<=30):
        raise ValueError('private_task_production_original_policy')
    with authority.connect() as db:
        row=db.execute('SELECT opaque_ref FROM epochs WHERE campaign=?',(policy['campaign_id'],)).fetchone()
    if row is None:raise ValueError('private_task_production_factory_not_committed')
    record=authority.resolve_formal_bundle(campaign=policy['campaign_id'],opaque_ref=row[0])
    if any(record[k]!=policy[v] for k,v in [('campaign_id','campaign_id'),('deployment_epoch','deployment_epoch'),
            ('config_digest','config_digest'),('deadline','campaign_deadline')]):
        raise ValueError('private_task_production_current_factory_scope')
    items=[item for item in record['private_plan']['body']['items']
        if item['phase']=='protected' and item['requirement']=='required']
    if not 1<=len(items)<=128 or policy['task_ordinal']>=len(items):
        raise ValueError('private_task_production_complete_plan_ordinal')
    deadline=datetime.fromisoformat(record['deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
        raise TimeoutError('private_task_production_original_clock')
    root=_directory('/task-production',21004,21004,0o750)
    target=_directory('/runtime-action-output',21004,21004,0o750)
    inbox=_directory('/private-launch-inbox',21004,21001,0o750)
    if any(root.iterdir()) or any(target.iterdir()) or any(inbox.iterdir()):
        raise RuntimeError('private_task_production_partial_or_original_no_reexecution')
    action={'kind':'FormalPrivateTaskPreparation','campaign_id':record['campaign_id'],'opaque_ref':row[0],
        'item_id':items[policy['task_ordinal']]['item_id']}
    action['digest']=digest_jcs(action);_publish(root/'prepare-action.json',action,21004)
    prepared=prepare_and_deliver(authority=authority,action_path=root/'prepare-action.json',
        policy_path='/private-policy/policy.json',lifecycle_review_path='/reviews/private-lifecycle.json',
        private_directory=Path(private_directory)/'current-tasks',proxy_inbox='/private-task-inbox',
        authority_directory=authority_directory,tokenizer_directory='/model')
    prepared.update(action_digest=action['digest'],producer_uid=21004);prepared['digest']=digest_jcs(prepared)
    projection=_directory(projection_directory,21004,21004,0o750)
    _publish(projection/(action['digest'][7:]+'.json'),prepared,21004)
    # Only this role observes the Proxy's current private transport receipt.
    # Waiting never redelivers the already delivered task.
    receipt=Path('/private-receipts')/(prepared['handoff_digest'][7:]+'.json');began=time.monotonic()
    while not os.path.lexists(receipt):
        if (time.monotonic()-began>=policy['maximum_wait_seconds']
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=120):
            raise TimeoutError('private_task_production_original_proxy_admission_unknown')
        time.sleep(0.1)
    launch={'kind':'FormalPrivateLaunchPreparation','preparation_digest':action['digest'],'campaign_id':record['campaign_id']}
    launch['digest']=digest_jcs(launch);_publish(root/'launch-action.json',launch,21004)
    result=prepare_launch_reference(authority=authority,action=launch,projection_directory=projection_directory,
        receipt_directory='/private-receipts',private_directory=Path(private_directory)/'current-tasks',
        controller_inbox='/private-launch-inbox')
    _publish(root/'launch.json',result,21004)
    runtime={'kind':'FormalPrivateRuntimePreparation','campaign_id':policy['campaign_id'],
        'launch_action_digest':launch['digest']}
    runtime['digest']=digest_jcs(runtime)
    if any(target.iterdir()):raise RuntimeError('private_task_production_existing_runtime_action_no_regeneration')
    _publish(target/'action.json',runtime,21004)
    current=result['launch']
    opaque={'kind':'EvaluatorOpaqueClosingAction','campaign_id':policy['campaign_id'],
        'deployment_epoch':policy['deployment_epoch'],'reference_digest':current['digest'],'stage':'runtime_prepare',
        'policy_digest':policy['digest'],'action_digest':runtime['digest'],'assignment_filename':'action.json',
        'qualification_issued':False}
    opaque['digest']=digest_jcs(opaque)
    _publish(Path('/private-launch-inbox')/'runtime-action.json',opaque,21001)
    # Private entry, item_id and session key remain solely in this role's output.
    return result
