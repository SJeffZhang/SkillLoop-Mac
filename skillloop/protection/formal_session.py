"""Protected Evaluator commits the current task's delivery and review state.

This process receives one sealed task assignment, never a development role
grant to the private authority. Unknown delivery is terminal for this session.
"""
import os
import re
from pathlib import Path
import stat

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs
from skillloop.proxy.qualification_authority import current_authority
from skillloop.protection.authority import ProtectionAuthority


def execute_session_action(*,assignment_path,private_directory,projection_directory,expected_action_digest,authority_directory):
    if os.geteuid()!=21004 or 21001 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('formal_session_actual_evaluator')
    # Full private assignments belong to Evaluator, never to Controller.
    owner=Path(assignment_path).parent.lstat().st_uid
    if owner not in {21001,21004}:raise PermissionError('formal_session_original_assignment_owner')
    job=read_owned(assignment_path,uid=owner,gid=21004,limit=8388608)
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}',expected_action_digest)
            or job['digest']!=expected_action_digest):
        raise ValueError('formal_session_sealed_action_digest')
    if owner==21001:
        if (set(job)!={'kind','policy_digest','digest'} or job.get('kind')!='ControllerPrivateClosingActionProduction'):
            raise PermissionError('formal_session_controller_opaque_production_only')
        policy=read_owned('/production-policy/policy.json',uid=21010,gid=21004,limit=262144)
        if policy['digest']!=job['policy_digest']:raise ValueError('formal_session_original_production_policy')
        from skillloop.protection.closing_actions import produce_closing_action
        authority=ProtectionAuthority(Path(private_directory)/'epoch-authority')
        return produce_closing_action(authority=authority,policy_path='/production-policy/policy.json',
            reference_path='/current-reference/reference.json',projection_directory=projection_directory,
            assignment_directory='/prepared-assignment',output_directory='/action-output',opaque_directory='/opaque-actions')
    if job.get('kind') == 'FormalPrivateArchive':
        from skillloop.runtime.task_archive import archive_reviewed_task
        if set(job)!={'kind','session_key','assignment_digest','digest'}:
            raise ValueError('private_archive_action_shape')
        authority=ProtectionAuthority(Path(private_directory)/'epoch-authority')
        pins=authority.formal_session_identity(job['session_key'])
        assignment=read_owned('/evaluation-assignment/assignment.json',uid=21004,gid=21004,limit=8388608)
        if (assignment['digest']!=job['assignment_digest'] or assignment['entry'].get('kind')!='protected'
                or assignment['entry']['digest']!=pins.get('entry_digest')
                or assignment['intent']['digest']!=pins.get('intent_digest')):
            raise ValueError('private_archive_original_session_binding')
        intent=assignment['intent']
        review=read_owned(Path('/reviews')/(intent['digest'][7:]+'.json'),uid=21005,gid=21004,limit=262144)
        policy=read_owned('/archive-policy/policy.json',uid=21010,gid=21004,limit=262144)
        bound=os.environ.get('SKILLLOOP_PRIVATE_MAX_EVIDENCE_BYTES','')
        seconds=os.environ.get('SKILLLOOP_PRIVATE_TIMEOUT_SECONDS','')
        if (not bound.isdecimal() or not seconds.isdecimal()
                or policy['maximum_bytes']+2097152>int(bound) or policy['timeout_seconds']>int(seconds)):
            raise ValueError('private_archive_complete_dispatch_reservation')
        return archive_reviewed_task(entry=assignment['entry'],intent=intent,capture=assignment['capture'],
            review=review,policy_path='/archive-policy/policy.json',engine=None,
            mount_attestation_path='/archive-mount/mount.json',sources={
                'runtime':'/private-raw','authority':'/authority/'+intent['digest'][7:],
                'evaluation':'/evaluation/'+intent['digest'][7:]+'.json',
                'gate':'/reviews/'+intent['digest'][7:]+'.json'})
    if job.get('kind') == 'FormalPrivateEvaluation':
        from datetime import datetime,timezone
        import time
        from skillloop.discovery.formal_evaluator import evaluate_capture
        if set(job)!={'kind','session_key','digest'}:raise ValueError('private_evaluation_action')
        authority=ProtectionAuthority(Path(private_directory)/'epoch-authority')
        pins=authority.formal_session_identity(job['session_key'])
        assignment=read_owned('/evaluation-assignment/assignment.json',uid=21004,gid=21004,limit=8388608)
        if (assignment.get('kind')!='FormalEvaluatorAssignment' or assignment['entry'].get('kind')!='protected'
                or assignment['entry']['digest']!=pins.get('entry_digest')
                or assignment['intent']['digest']!=pins.get('intent_digest')):
            raise ValueError('private_evaluation_original_delivered_assignment')
        with authority.connect() as db:
            state=db.execute('SELECT state FROM sessions WHERE key=?',(job['session_key'],)).fetchone()
        if state!=('delivered',):raise ValueError('private_evaluation_session_not_delivered')
        deadline=datetime.fromisoformat(assignment['campaign_deadline'].replace('Z','+00:00'))
        wait=assignment['snapshot_wait_seconds']
        if type(wait) is not int or not 1<=wait<=60 or deadline.tzinfo is None:raise ValueError('private_evaluation_snapshot_budget')
        snapshot=Path('/authority')/pins['intent_digest'][7:];started=time.monotonic()
        while not os.path.lexists(snapshot/'snapshot.json'):
            if time.monotonic()-started>=wait or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
                raise TimeoutError('private_evaluation_snapshot_not_committed')
            time.sleep(0.2)
        return evaluate_capture(entry=assignment['entry'],intent=assignment['intent'],capture=assignment['capture'],
            run_directory='/private-raw',snapshot_directory=snapshot,output_directory='/evaluation',
            maximum_database_bytes=assignment['maximum_database_bytes'])
    if job.get('kind') == 'FormalPrivateCapturePreparation':
        from skillloop.protection.private_capture import prepare_capture
        capacity=os.environ.get('SKILLLOOP_PRIVATE_MAX_EVIDENCE_BYTES','')
        seconds=os.environ.get('SKILLLOOP_PRIVATE_TIMEOUT_SECONDS','')
        if not capacity.isdecimal() or not seconds.isdecimal():
            raise ValueError('private_capture_frozen_dispatch_bounds')
        authority=ProtectionAuthority(Path(private_directory)/'epoch-authority')
        return prepare_capture(authority=authority,action=job,projection_directory=projection_directory,
            private_directory=Path(private_directory)/'current-tasks',handoff_directory='/runtime-handoff',
            completion_directory='/private-completion',raw_directory='/private-raw',
            assignment_directory='/evaluation-assignment',maximum_bytes=int(capacity),maximum_files=4096,
            timeout_seconds=int(seconds))
    if job.get('kind') == 'FormalPrivateAuthoritySnapshot':
        snapshot_fields={'kind','campaign_id','opaque_ref','maximum_database_bytes','timeout_seconds','digest'}
        if set(job) not in (snapshot_fields,snapshot_fields|{'session_key'}):
            raise ValueError('formal_private_authority_snapshot_action')
        capacity=os.environ.get('SKILLLOOP_PRIVATE_MAX_EVIDENCE_BYTES','')
        seconds=os.environ.get('SKILLLOOP_PRIVATE_TIMEOUT_SECONDS','')
        if (not capacity.isdecimal() or not seconds.isdecimal()
                or type(job['maximum_database_bytes']) is not int or job['maximum_database_bytes']<1
                or type(job['timeout_seconds']) is not int or job['timeout_seconds']<1
                or job['timeout_seconds']>int(seconds)
                or 2*job['maximum_database_bytes']+262144>int(capacity)):
            raise ValueError('formal_private_snapshot_complete_dispatch_reservation')
        authority=ProtectionAuthority(Path(private_directory)/'epoch-authority')
        if 'session_key' in job:
            pins=authority.formal_session_identity(job['session_key'])
            with authority.connect() as db:
                state=db.execute('SELECT state FROM sessions WHERE key=?',(job['session_key'],)).fetchone()
            record=authority.resolve_formal_bundle(campaign=job['campaign_id'],opaque_ref=job['opaque_ref'])
            if (state!=('complete',) or pins['campaign']!=job['campaign_id']
                    or pins['private_record_digest']!=record['digest']):
                raise ValueError('formal_private_snapshot_original_complete_session')
        return authority.export_gate_snapshot(campaign=job['campaign_id'],opaque_ref=job['opaque_ref'],
            output_directory='/gate-authority',maximum_bytes=job['maximum_database_bytes'],
            timeout_seconds=job['timeout_seconds'])
    if job.get('kind') == 'FormalPrivateRuntimePreparation':
        from skillloop.protection.current_task import prepare_runtime_request
        authority = ProtectionAuthority(Path(private_directory) / 'epoch-authority')
        return prepare_runtime_request(authority=authority, action=job,
            projection_directory=projection_directory, private_directory=Path(private_directory) / 'current-tasks',
            started_directory='/private-started', runtime_directory='/runtime-current',
            authority_directory=authority_directory)
    if job.get('kind') == 'FormalPrivateLaunchPreparation':
        from skillloop.protection.current_task import prepare_launch_reference
        authority = ProtectionAuthority(Path(private_directory) / 'epoch-authority')
        return prepare_launch_reference(authority=authority, action=job,
            projection_directory=projection_directory, receipt_directory='/private-receipts',
            private_directory=Path(private_directory) / 'current-tasks',
            controller_inbox='/private-launch-inbox')
    if job.get('kind') == 'FormalPrivateTaskPreparation':
        from skillloop.protection.current_task import prepare_and_deliver
        authority = ProtectionAuthority(Path(private_directory) / 'epoch-authority')
        prepared = prepare_and_deliver(authority=authority, action_path=assignment_path,
            policy_path='/private-policy/policy.json', lifecycle_review_path='/reviews/private-lifecycle.json',
            private_directory=Path(private_directory) / 'current-tasks',
            proxy_inbox='/private-task-inbox', authority_directory=authority_directory, tokenizer_directory='/model')
        from skillloop.protection.current_task import _directory, _publish
        output = _directory(projection_directory, 21004, 21004, 0o750)
        prepared.update(action_digest=job['digest'], producer_uid=21004)
        prepared['digest'] = digest_jcs(prepared)
        _publish(output / (job['digest'][7:] + '.json'), prepared, 21004)
        return prepared
    fields={'kind','action','campaign_id','private_record_digest','subject_digest','case_digest',
            'repetition','delivery_assignment_path','session_key','evaluation_path','gate_review_path','digest'}
    if set(job)!=fields or job['kind']!='FormalPrivateSessionAction' or job['action'] not in {'deliver','complete','unknown'}:
        raise ValueError('formal_session_action_shape')
    output=Path(projection_directory);info=output.lstat()
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21004 or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('formal_session_private_evaluator_projection')
    authority=ProtectionAuthority(Path(private_directory)/'epoch-authority')
    with authority.connect() as db:
        row=db.execute('SELECT record FROM formal_private_bundles WHERE campaign=?',(job['campaign_id'],)).fetchone()
    if row is None:raise ValueError('formal_session_committed_bundle_required')
    record=decode_json(row[0])
    if (record.get('digest')!=job['private_record_digest']
            or record['digest']!=digest_jcs({k:v for k,v in record.items() if k!='digest'})
            or record.get('kind')!='FormalPrivateFactoryBundle'):
        raise ValueError('formal_session_committed_bundle_identity')
    with current_authority(authority_directory,epoch=record['deployment_epoch'],
            config_digest=record['config_digest'],trust_revision=record['trust_revision'],
            approval_digests=set(record['approval_digests']),campaign=record['campaign_id']) as live:
        heads=[row for row in live.get('plan_heads',[]) if row['campaign_id']==record['campaign_id']]
        if len(heads)!=1 or heads[0]['plan_digest']!=record['development_plan_digest']:
            raise ValueError('formal_session_frozen_development_head_changed')
        if job['action']=='deliver':
            if (job['delivery_assignment_path']!='/assignment/delivery.json'
                    or any(job[k] is not None for k in ('session_key','evaluation_path','gate_review_path'))):
                raise ValueError('formal_session_current_delivery_mount')
            key=authority.reserve_formal_session(campaign=job['campaign_id'],
                private_record_digest=job['private_record_digest'],subject=job['subject_digest'],
                case=job['case_digest'],repetition=job['repetition'])
            result=authority.deliver_formal_session(key=key,assignment_path=job['delivery_assignment_path'])
            delivery=read_owned(job['delivery_assignment_path'],uid=21004,gid=21004,limit=8388608)
            result.update(intent_digest=delivery['intent']['digest'],entry_digest=delivery['entry']['digest'])
        else:
            if job['delivery_assignment_path'] is not None:raise ValueError('formal_session_terminal_assignment')
            key=job['session_key']
            pins=authority.formal_session_identity(key)
            if any(pins[a]!=job[b] for a,b in (('campaign','campaign_id'),('private_record_digest','private_record_digest'),
                    ('subject','subject_digest'),('case','case_digest'),('repetition','repetition'))):
                raise ValueError('formal_session_terminal_identity')
            if job['action']=='complete':
                if (job['evaluation_path']!='/evaluation/'+pins['intent_digest'][7:]+'.json'
                        or job['gate_review_path']!='/reviews/'+pins['intent_digest'][7:]+'.json'):
                    raise ValueError('formal_session_terminal_mount')
                state=authority.finish_formal_session(key=key,evaluation_path=job['evaluation_path'],gate_review_path=job['gate_review_path'])
            else:
                if job['evaluation_path'] is not None or job['gate_review_path'] is not None:
                    raise ValueError('formal_session_unknown_has_no_complete_review')
                state=authority.finish_formal_session(key=key)
            result={'key':key,'state':state,'automatic_reexecution_allowed':False}
        receipt={'kind':'FormalPrivateSessionReceipt','action_digest':job['digest'],'action':job['action'],
            'campaign_id':job['campaign_id'],'private_record_digest':job['private_record_digest'],
            'subject_digest':job['subject_digest'],'case_digest':job['case_digest'],'repetition':job['repetition'],
            'result':result,'producer_uid':21004,'qualification_issued':False}
        receipt['digest']=digest_jcs(receipt)
        fd=os.open(output/(job['digest'][7:]+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),-1,21004);os.fchmod(stream.fileno(),0o640)
            stream.write(canonical_json_line(receipt));stream.flush();os.fsync(stream.fileno())
        fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        return receipt

def main():
    os.umask(0o077)
    try:
        execute_session_action(assignment_path='/assignment/action.json',private_directory='/private',
            projection_directory='/session-projection',
            expected_action_digest=os.environ.get('SKILLLOOP_PRIVATE_ACTION_DIGEST',''),
            authority_directory='/authority-projection')
    except BaseException as error:
        import traceback
        try:
            output=Path('/session-projection');info=output.lstat()
            reference=os.environ.get('SKILLLOOP_PRIVATE_ACTION_DIGEST','')
            if (os.geteuid()==21004 and info.st_uid==21004 and info.st_gid==21004
                    and stat.S_IMODE(info.st_mode)==0o750 and not output.is_symlink()
                    and re.fullmatch(r'sha256:[0-9a-f]{64}',reference)):
                value={'kind':'PrivateSessionExecutionFailure','action_digest':reference,
                    'error_type':type(error).__name__,'private_traceback':traceback.format_exc(),
                    'automatic_reexecution_allowed':False}
                value['digest']=digest_jcs(value)
                fd=os.open(output/(reference[7:]+'.failure.json'),
                    os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(canonical_json_line(value));stream.flush();os.fsync(stream.fileno())
                fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
        except BaseException as custody_error:
            error.add_note('private_failure_evidence_preservation_error:'+type(custody_error).__name__)
        raise


if __name__=='__main__':main()
