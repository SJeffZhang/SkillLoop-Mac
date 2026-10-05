"""Controller execution of an admitted formal task, using the real Proxy lease.

Campaign/evidence reservation and original spending admission belong to the
whole-campaign dispatcher. This entry neither issues approval nor creates a
local authority database. Its output awaits independent evaluator/Gate review.
"""
from __future__ import annotations

import base64
import os
import stat
import hashlib
from pathlib import Path

from skillloop.discovery.mutation import compile_mutation
from skillloop.loader import ApprovedPackageLoader, validate_source_admission
from skillloop.families.registry import FamilyRegistry
from skillloop.protection.mac_runtime import container_execute
from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs, validate_envelope
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.task_controller import FormalTaskController
from skillloop.runtime.docker_api import DockerEngine
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.evaluation_dispatch import dispatch_evaluation, dispatch_task_gate
from skillloop.runtime.formal_retirement import retire_reviewed_task


def execute_admitted(entry, intent, started, output, *, resource_context, tokenizer, controller, ledger,
                     evaluator_policy, evaluator_assignment_directory, gate_policy, gate_journal_directory,
                     gate_review_path, retirement_journal_directory,archive_policy_path,archive_sources,archive_gate_policy,
                     archive_gate_journal_directory,archive_review_path,private_session_context=None):
    if entry.get('kind')=='protected':
        raise PermissionError('protected_entry_requires_private_evaluator_dispatch')
    dispatch_state={'attempted':False}
    try:
        return _execute_admitted(entry,intent,started,output,resource_context=resource_context,
            tokenizer=tokenizer,controller=controller,ledger=ledger,evaluator_policy=evaluator_policy,
            evaluator_assignment_directory=evaluator_assignment_directory,gate_policy=gate_policy,
            gate_journal_directory=gate_journal_directory,gate_review_path=gate_review_path,
            retirement_journal_directory=retirement_journal_directory,dispatch_state=dispatch_state,
                archive_policy_path=archive_policy_path,archive_sources=archive_sources,
                archive_gate_policy=archive_gate_policy,archive_gate_journal_directory=archive_gate_journal_directory,
            archive_review_path=archive_review_path,private_session_context=private_session_context)
    except BaseException as error:
        # No Runtime Engine request has been sent before this boundary.
        # An issued Lease must be fenced when preflight fails.
        # Once Runtime dispatch is attempted its identity/lifecycle journal, rather than
        # this shortcut, must establish whether a worker can still be running.
        if not dispatch_state['attempted']:
            try:controller.cancel_before_runtime(intent,started)
            except BaseException as secondary:
                error.add_note('formal_pre_dispatch_cancel_requires_recovery:'+type(secondary).__name__)
        raise


def _execute_admitted(entry, intent, started, output, *, resource_context, tokenizer, controller, ledger,
                      evaluator_policy, evaluator_assignment_directory, gate_policy, gate_journal_directory,
                      gate_review_path, retirement_journal_directory, dispatch_state,archive_policy_path,archive_sources,archive_gate_policy,
                      archive_gate_journal_directory,archive_review_path,private_session_context):
    if os.geteuid()!=21001:
        raise PermissionError('formal_runtime_controller_role')
    if not isinstance(tokenizer,ExactLocalTokenizer):
        raise ValueError('formal_native_tokenizer_required')
    if not isinstance(controller,FormalTaskController) or controller.epoch!=intent['deployment_epoch']:
        raise ValueError('formal_business_closure_controller_required')
    config=entry['config'];compiled=entry['compiled']
    if entry.get('kind')=='protected' or private_session_context is not None:
        raise PermissionError('protected_entry_requires_private_evaluator_dispatch')
    if (evaluator_policy.get('digest')!=digest_jcs({k:v for k,v in evaluator_policy.items() if k!='digest'})
            or evaluator_policy.get('entry_digest')!=entry['digest']
            or evaluator_policy.get('deployment_epoch')!=config['deployment_epoch']):
        raise ValueError('formal_independent_evaluator_dispatch_required')
    if (gate_policy.get('digest')!=digest_jcs({k:v for k,v in gate_policy.items() if k!='digest'})
            or gate_policy.get('entry_digest')!=entry['digest']
            or gate_policy.get('deployment_epoch')!=config['deployment_epoch']
            or gate_policy.get('campaign_deadline')!=evaluator_policy.get('campaign_deadline')):
        raise ValueError('formal_independent_gate_dispatch_required')
    from datetime import datetime,timezone
    deadline=datetime.fromisoformat(gate_policy['campaign_deadline'].replace('Z','+00:00'))
    if (archive_gate_policy.get('digest')!=digest_jcs({k:v for k,v in archive_gate_policy.items() if k!='digest'})
            or archive_gate_policy.get('entry_digest')!=entry['digest']
            or archive_gate_policy.get('campaign_deadline')!=gate_policy['campaign_deadline']
            or archive_gate_policy.get('image')!=config['mac_runtime_image']):
        raise ValueError('formal_archive_gate_dispatch_binding')
    needed=config['worker_deadline_seconds']+evaluator_policy['timeout_seconds']+gate_policy['timeout_seconds']+archive_gate_policy['timeout_seconds']+180
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=needed:
        raise TimeoutError('formal_full_task_and_review_budget_required')
    if (not isinstance(ledger,SpendingLedger) or ledger.campaign_started_at is None
            or ledger.victim_seconds!=config['worker_deadline_seconds']):
        raise ValueError('formal_original_spending_clock_required')
    if 21004 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('formal_evaluator_read_group_required')
    for field in ('maximum_runtime_evidence_bytes','maximum_runtime_evidence_files'):
        if type(config.get(field)) is not int or not 1<=config[field]<=9007199254740991:
            raise ValueError('formal_runtime_frozen_evidence_capacity_required')
    if (type(config.get('runtime_evidence_volume_bytes')) is not int
            or not 4096<=config['runtime_evidence_volume_bytes']<=2147483648
            or config['maximum_runtime_evidence_bytes']>config['runtime_evidence_volume_bytes']):
        raise ValueError('formal_runtime_evidence_volume_binding')
    if intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'}):
        raise ValueError('formal_runtime_intent_changed')
    if config.get('whole_flow_required') is not True or started['intent_digest']!=intent['digest']:
        raise ValueError('formal_admitted_runtime_required')
    if started['digest']!=digest_jcs({k:v for k,v in started.items() if k!='digest'}):
        raise ValueError('formal_start_receipt_digest')
    if resource_context.get('proxy_server_uid')!=21003:
        raise ValueError('formal_runtime_proxy_identity')
    if (resource_context.get('tokenizer_mount')!=evaluator_policy['mounts']['tokenizer']
            or resource_context.get('tokenizer_mount')!=gate_policy['mounts']['tokenizer']):
        raise ValueError('formal_runtime_independent_tokenizer_volume_binding')
    if (intent['deployment_epoch']!=config['deployment_epoch']
            or intent['plan']['digest']!=entry['plan']['digest']
            or intent['suite']['digest']!=compiled['suite']['digest']
            or intent['run_request']['body']['case_digest']!=compiled['cases'][entry['case_id']]['digest']
            or intent['run_request']['body']['repetition_index']!=entry['repetition']):
        raise ValueError('formal_runtime_frozen_entry')
    output=Path(output)
    parent=output.parent.lstat()
    if (not output.is_absolute() or output.is_symlink() or parent.st_uid!=21001
            or output.parent.is_symlink()):
        raise PermissionError('formal_runtime_output_owner')
    output.mkdir(mode=0o700)
    admission=entry['source_admission']
    validate_source_admission(admission,config,compiled['subject_digest'])
    package={k:base64.b64decode(v,validate=True) for k,v in admission['package_files'].items()}
    loader=ApprovedPackageLoader(approved_sources=admission['approved_sources'],
        reference_resource_ids=admission['reference_resource_ids'],approved_subjects=admission.get('approved_subjects'))
    selected=loader.select(admission['source_snapshot'],package,admission['manifest'],
        profile_id=entry['profile'],family_id=FamilyRegistry().profile(entry['profile'])['family_id'])
    selected.check_binding(intent['binding'])
    if digest_bytes(package['SKILL.md'])!=compiled['skill_digest']:
        raise ValueError('formal_runtime_instruction_identity')
    validate_envelope(started['lease'])
    lease=started['lease'];expiry=datetime.fromisoformat(lease['body']['expires_at'].replace('Z','+00:00'))
    if (lease['kind']!='Lease' or lease['body']['state']!='active'
            or lease['body']['run_id']!=intent['binding']['body']['run_id']
            or lease['body']['campaign_id']!=intent['campaign_id']
            or lease['body']['fencing_token']!=1 or expiry.tzinfo is None):
        raise ValueError('formal_runtime_actual_lease_binding')
    if (expiry-datetime.now(timezone.utc)).total_seconds()<=config['worker_deadline_seconds']+10:
        raise ValueError('formal_runtime_actual_lease_cannot_fit_worker')
    mutation_spec=compiled['mutations'].get(entry['case_id'])
    inputs={k:base64.b64decode(v,validate=True) for k,v in intent['input_resources'].items()}
    notes_id=FamilyRegistry().profile(entry['profile'])['input_bindings']['notes']
    mutation=(compile_mutation(mutation_spec,source_bytes=inputs[notes_id],profile_id=entry['profile'],
                               count_tokens=tokenizer.count_text) if mutation_spec else None)
    capture={'kind':'FormalRuntimeCapture','entry_digest':entry['digest'],'intent_digest':intent['digest'],
        'source_admission_digest':digest_jcs(admission),'approval_digest':started['approval_digest'],
        'lease':started['lease'],'trust_revision':started['trust_revision'],'result':None,
        'evaluation_complete':False,'independent_gate_complete':False}
    def save_capture():
        capture['digest']=digest_jcs({k:v for k,v in capture.items() if k!='digest'})
        temporary=output/'runtime-capture.pending'
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(capture));stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,output/'runtime-capture.json')
    save_capture()
    closure_attempted=False;capture_sealed=False
    def close_business():
        nonlocal closure_attempted
        closure_attempted=True
        lifecycle_path=output/'runtime-lifecycle.json'
        fd=os.open(lifecycle_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=21001 or info.st_size>262144:
                raise PermissionError('formal_runtime_lifecycle_custody')
            lifecycle=decode_json(stream.read(262145))
        if (lifecycle.get('digest')!=digest_jcs({k:v for k,v in lifecycle.items() if k!='digest'})
                or lifecycle.get('run_request_digest')!=intent['run_request']['digest']
                or lifecycle.get('deployment_epoch')!=controller.epoch
                or lifecycle.get('image')!=config['mac_runtime_image']):
            raise ValueError('formal_runtime_lifecycle_binding')
        worker=lifecycle.get('worker_id')
        if worker is None:
            # A partially initialized volume is retained. A separate recovery
            # decision must prove no worker exists before cancelling its lease.
            raise RuntimeError('formal_runtime_worker_identity_unknown_preserve_custody')
        engine=DockerEngine(config.get('docker_engine_socket','/var/run/docker.sock'))
        closure=controller.finish(intent,started,runtime_container_id=worker,
            keeper_id=lifecycle.get('keeper_id'),run_volume=lifecycle.get('run_volume'),
            operation_id='finish-'+intent['digest'][7:],engine=engine)
        capture['business_closure']=closure
        capture['resource_lifecycle_digest']=lifecycle['digest']
        save_capture()
    def grant_evaluator():
        if 21004 not in set(os.getgroups())|{os.getegid()}:
            raise PermissionError('formal_evaluator_read_group_required')
        inventory={};total=0;paths=[]
        for root,dirs,files in os.walk(output,followlinks=False):
            for name in sorted(dirs+files):
                path=Path(root)/name;info=path.lstat()
                if (info.st_uid!=21001 or path.is_symlink()
                        or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
                    raise PermissionError('formal_raw_evidence_owner')
                paths.append(path)
                if len(paths)>config['maximum_runtime_evidence_files']:
                    raise ValueError('formal_raw_evidence_file_capacity')
                if stat.S_ISREG(info.st_mode):
                    total+=info.st_size
                    if total>config['maximum_runtime_evidence_bytes']:
                        raise ValueError('formal_raw_evidence_byte_capacity')
                    h=hashlib.sha256()
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                    with os.fdopen(fd,'rb') as stream:
                        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
                    inventory[str(path.relative_to(output))]={'digest':'sha256:'+h.hexdigest(),'bytes':info.st_size}
        grant={'kind':'FormalEvaluatorReadGrant','controller_uid':21001,'evaluator_gid':21004,
            'intent_digest':intent['digest'],'runtime_capture_digest':capture['digest'],
            'business_closure_digest':capture['business_closure']['digest'],'files':inventory,
            'total_bytes':total,'independent_gate_complete':False,'evidence_released':False}
        grant['digest']=digest_jcs(grant)
        if len(paths)+1>config['maximum_runtime_evidence_files']:
            raise ValueError('formal_read_grant_file_capacity')
        grant_bytes=canonical_json_line(grant)
        if len(grant_bytes)>2097152 or total+len(grant_bytes)>config['maximum_runtime_evidence_bytes']:
            raise ValueError('formal_read_grant_byte_capacity')
        path=output/'evaluator-read-grant.json'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(grant_bytes);stream.flush();os.fsync(stream.fileno())
        for path in [*paths,path,output]:
            os.chown(path,-1,21004)
            os.chmod(path,0o750 if path.is_dir() else 0o640)
        fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    try:
        # A durable consumed attempt precedes every helper/worker creation.
        # Failed init, lost response and unknown execution stay spent.
        spending=ledger.consume(entry['entry_id'],0)
        capture['spending_state_digest']=digest_jcs(spending)
        save_capture()
        dispatch_state['attempted']=True
        result=container_execute(output,entry['profile'],package['SKILL.md'],intent['run_request'],intent['binding'],
            config,mutation,0,config['deployment_epoch'],resource_context=resource_context,
            imported_selection=selected,run_lease=started['lease'],trust_revision=started['trust_revision'])
        capture['result']=result
        save_capture()
        close_business()
        grant_evaluator()
        capture_sealed=True
        evaluation_process=dispatch_evaluation(entry=entry,intent=intent,capture=capture,
            assignment_directory=evaluator_assignment_directory,policy=evaluator_policy,
            engine=DockerEngine(config.get('docker_engine_socket','/var/run/docker.sock')))
        engine=DockerEngine(config.get('docker_engine_socket','/var/run/docker.sock'))
        gate_process=dispatch_task_gate(entry=entry,intent=intent,policy=gate_policy,
            journal_directory=gate_journal_directory,engine=engine)
        def finish_resources():
            return retire_reviewed_task(entry=entry,intent=intent,capture=capture,review_path=gate_review_path,
                journal_directory=retirement_journal_directory,engine=engine,
                role_processes={'protected_evaluator':evaluation_process['inspection'],'gate':gate_process},
                archive_policy_path=archive_policy_path,archive_sources=archive_sources,
                archive_gate_policy=archive_gate_policy,archive_gate_journal_directory=archive_gate_journal_directory,
                archive_review_path=archive_review_path)
        try:retirement=finish_resources()
        except (ConnectionError,TimeoutError) as cleanup_error:
            # Only cleanup's own durable, independently reviewed intent may be
            # reconciled here. No inference, evaluation or export is repeated.
            if not (Path(retirement_journal_directory)/'retirement-intent.json').exists():raise
            from skillloop.runtime.proposal_dispatch import _save
            _save(Path(retirement_journal_directory),'original-transport-failure.json',
                {'kind':'FormalRetirementTransportFailure','intent_digest':intent['digest'],
                 'error_type':type(cleanup_error).__name__,'automatic_model_reexecution_allowed':False})
            retirement=finish_resources()
        if retirement.get('budget_closure')!='within_original_budget':
            raise TimeoutError('formal_retirement_original_budget_expired')
        return capture
    except BaseException as error:
        # Evaluator failures have their own dispatch journal. Once handed off,
        # never mutate the Runtime capture or break its signed read inventory.
        if not capture_sealed:
            capture['runtime_failure_type']=type(error).__name__
            try:save_capture()
            except BaseException as secondary:error.add_note('formal_capture_preservation_error:'+type(secondary).__name__)
        # If closure itself failed, its journal already records an uncertain
        # cancel; never resend it or turn that uncertainty into a completed run.
        if not closure_attempted and dispatch_state['attempted']:
            try:close_business()
            except BaseException as secondary:
                error.add_note('formal_business_closure_requires_recovery:'+type(secondary).__name__)
        raise
