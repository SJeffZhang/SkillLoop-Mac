"""Evaluator produces current closing actions from its private authority.

Controller receives only a sealed dispatch reference. Session keys, case pins,
prepared captures and execution assignments never leave private role custody.
"""
from datetime import datetime,timezone
import os
from pathlib import Path

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory,_publish

STAGES={'capture','evaluate','task_gate','session_complete','archive','archive_gate',
        'terminal_authority_snapshot','retirement_gate'}


def produce_closing_action(*,authority,policy_path,reference_path,projection_directory,
                           assignment_directory,output_directory,opaque_directory):
    if os.geteuid()!=21004 or authority.readonly:
        raise PermissionError('private_closing_production_actual_evaluator')
    policy=read_owned(policy_path,uid=21010,gid=21004,limit=262144)
    fields={'kind','campaign_id','deployment_epoch','config_digest','campaign_deadline','stage',
        'maximum_database_bytes','snapshot_wait_seconds','maximum_archive_bytes','maximum_archive_files','digest'}
    if (set(policy)!=fields or policy['kind']!='AdminPrivateClosingActionProduction'
            or policy['stage'] not in STAGES
            or type(policy['maximum_database_bytes']) is not int or not 1<=policy['maximum_database_bytes']<=536870912
            or type(policy['snapshot_wait_seconds']) is not int or not 1<=policy['snapshot_wait_seconds']<=60
            or type(policy['maximum_archive_bytes']) is not int or not 1<=policy['maximum_archive_bytes']<=2147483648
            or type(policy['maximum_archive_files']) is not int or not 1<=policy['maximum_archive_files']<=65536):
        raise ValueError('private_closing_production_frozen_policy')
    reference=read_owned(reference_path,uid=21004,gid=21001,limit=262144)
    if (reference.get('kind')!='EvaluatorOpaqueRunReference'
            or any(reference.get(k)!=policy[k] for k in ('campaign_id','deployment_epoch'))):
        raise ValueError('private_closing_production_current_reference')
    with authority.connect() as db:
        claim=db.execute('SELECT m.session_key,m.launch_action,m.launch_digest,s.state FROM formal_runtime_materializations m JOIN sessions s ON s.key=m.session_key WHERE m.opaque_ref=?',
            (reference['opaque_ref'],)).fetchone()
        epoch=db.execute('SELECT opaque_ref FROM epochs WHERE campaign=?',(policy['campaign_id'],)).fetchone()
    if claim is None or epoch is None or claim[2]!=reference['digest']:
        raise ValueError('private_closing_production_original_claim')
    key,launch_action,_,state=claim
    record=authority.resolve_formal_bundle(campaign=policy['campaign_id'],opaque_ref=epoch[0])
    if (record['deployment_epoch']!=policy['deployment_epoch'] or record['config_digest']!=policy['config_digest']
            or record['deadline']!=policy['campaign_deadline']):
        raise ValueError('private_closing_production_original_bundle')
    deadline=datetime.fromisoformat(record['deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or deadline<=datetime.now(timezone.utc):
        raise TimeoutError('private_closing_production_original_clock')
    pins=authority.formal_session_identity(key)
    mapping=read_owned(Path(projection_directory)/(launch_action[7:]+'.launch.json'),uid=21004,gid=21004,limit=262144)
    if (mapping.get('kind')!='PrivateRunLaunchMapping' or mapping.get('session_key')!=key
            or mapping.get('action_digest')!=launch_action or mapping.get('launch')!=reference
            or pins.get('campaign')!=policy['campaign_id'] or pins.get('private_record_digest')!=record['digest']
            or mapping.get('intent_digest')!=pins.get('intent_digest')):
        raise ValueError('private_closing_production_private_binding')
    stage=policy['stage']
    if stage=='terminal_authority_snapshot' and policy['snapshot_wait_seconds']>30:
        raise ValueError('private_closing_production_authority_snapshot_timeout')
    if state!=('complete' if stage in {'archive','archive_gate','terminal_authority_snapshot','retirement_gate'} else 'delivered'):
        raise ValueError('private_closing_production_original_session_state')
    filename='action.json'
    if stage=='capture':
        action={'kind':'FormalPrivateCapturePreparation','launch_action_digest':launch_action,
            'campaign_id':policy['campaign_id'],'maximum_database_bytes':policy['maximum_database_bytes'],
            'snapshot_wait_seconds':policy['snapshot_wait_seconds']}
    elif stage=='evaluate':action={'kind':'FormalPrivateEvaluation','session_key':key}
    elif stage in {'task_gate','archive'}:
        assignment=read_owned(Path(assignment_directory)/'assignment.json',uid=21004,gid=21004,limit=8388608)
        if (assignment.get('kind')!='FormalEvaluatorAssignment'
                or assignment.get('entry',{}).get('digest')!=pins.get('entry_digest')
                or assignment.get('intent',{}).get('digest')!=pins.get('intent_digest')
                or assignment.get('campaign_deadline')!=policy['campaign_deadline']):
            raise ValueError('private_closing_production_actual_capture_assignment')
        if stage=='task_gate':action={k:v for k,v in assignment.items() if k!='digest'};filename='assignment.json'
        else:action={'kind':'FormalPrivateArchive','session_key':key,'assignment_digest':assignment['digest']}
    elif stage=='session_complete':
        action={'kind':'FormalPrivateSessionAction','action':'complete','campaign_id':pins['campaign'],
            'private_record_digest':pins['private_record_digest'],'subject_digest':pins['subject'],
            'case_digest':pins['case'],'repetition':pins['repetition'],'delivery_assignment_path':None,
            'session_key':key,'evaluation_path':'/evaluation/'+pins['intent_digest'][7:]+'.json',
            'gate_review_path':'/reviews/'+pins['intent_digest'][7:]+'.json'}
    elif stage=='archive_gate':
        action={'kind':'FormalPrivateArchiveReview','intent_digest':pins['intent_digest'],
            'campaign_deadline':record['deadline'],'maximum_bytes':policy['maximum_archive_bytes'],
            'maximum_files':policy['maximum_archive_files']};filename='assignment.json'
    elif stage=='terminal_authority_snapshot':
        action={'kind':'FormalPrivateAuthoritySnapshot','campaign_id':policy['campaign_id'],'opaque_ref':epoch[0],
            'session_key':key,'maximum_database_bytes':policy['maximum_database_bytes'],
            'timeout_seconds':policy['snapshot_wait_seconds']}
    else:
        action={'kind':'FormalPrivateRetirementAuthorization','session_key':key,'campaign_id':policy['campaign_id'],
            'opaque_ref':reference['opaque_ref'],'factory_ref':epoch[0],'launch_action_digest':launch_action,
            'intent_digest':pins['intent_digest']}
    action['digest']=digest_jcs(action)
    root=_directory(output_directory,21004,21004,0o750)
    opaque=_directory(opaque_directory,21004,21001,0o750)
    if any(root.iterdir()) or any(opaque.iterdir()):
        raise RuntimeError('private_closing_production_original_or_partial_publication_no_regeneration')
    _publish(root/filename,action,21004)
    receipt={'kind':'EvaluatorOpaqueClosingAction','campaign_id':policy['campaign_id'],
        'deployment_epoch':policy['deployment_epoch'],'reference_digest':reference['digest'],
        'stage':stage,'policy_digest':policy['digest'],'action_digest':action['digest'],
        'assignment_filename':filename,'qualification_issued':False}
    receipt['digest']=digest_jcs(receipt);_publish(opaque/'action.json',receipt,21001)
    return receipt
