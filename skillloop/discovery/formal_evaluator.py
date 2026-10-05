"""Independent Evaluator reduction of a complete formal Runtime capture."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import hashlib
import time
import re
from datetime import datetime,timezone

from skillloop.discovery.authority_snapshot import PublicationSnapshot
from skillloop.discovery.evaluator import evaluate_run
from skillloop.families.builders import build_artifact
from skillloop.families.oracle import validate_artifact
from skillloop.families.registry import FamilyRegistry
from skillloop.protocol import canonical_json_line, decode_json, digest_jcs, validate_envelope
from skillloop.runtime.mac_entry import verify_formal_entry, verify_protected_entry


def evaluate_capture(*, entry, intent, capture, run_directory, snapshot_directory,
                     output_directory, maximum_database_bytes, review_only=False):
    if type(review_only) is not bool or os.geteuid()!=(21005 if review_only else 21004):
        raise PermissionError('formal_evaluator_or_independent_gate_uid_required')
    config=entry['config'];compiled=entry['compiled']
    private=entry.get('kind')=='protected'
    raw_owner=21004 if private else 21001
    from scripts.dgx_m6_repair import source_index
    if digest_jcs(source_index(Path(__file__).resolve().parents[2]))!=entry['source_index_digest']:
        raise ValueError('formal_evaluation_actual_source_changed')
    verifier=verify_protected_entry if entry.get('kind')=='protected' else verify_formal_entry
    verifier(entry,image=config['mac_runtime_image'],source_digest=entry['source_index_digest'],
             model_port=config['model_service_port'])
    if intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'}):
        raise ValueError('formal_evaluation_intent_changed')
    if (config.get('whole_flow_required') is not True or capture.get('kind')!='FormalRuntimeCapture'
            or capture['digest']!=digest_jcs({k:v for k,v in capture.items() if k!='digest'})
            or capture['source_admission_digest']!=digest_jcs(entry['source_admission'])
            or capture['entry_digest']!=entry['digest'] or capture['intent_digest']!=intent['digest']
            or intent['config']!=config or intent['plan']!=entry['plan']):
        raise ValueError('formal_evaluation_frozen_capture')
    directory=Path(run_directory)
    if not directory.is_absolute() or directory.is_symlink():
        raise PermissionError('formal_evaluation_raw_directory')
    # Raw evidence is assigned by the Controller only after actual export.
    # Every path must have the same readonly evaluator grant, not just the root.
    paths=[directory]
    for root,dirs,files in os.walk(directory,followlinks=False):
        for name in dirs+files:
            paths.append(Path(root)/name)
            if len(paths)>config['maximum_runtime_evidence_files']+2:
                raise ValueError('formal_evaluation_raw_file_capacity')
    for path in paths:
        info=path.lstat()
        expected_mode=0o750 if stat.S_ISDIR(info.st_mode) else 0o640
        if (path.is_symlink() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or info.st_uid!=raw_owner or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=expected_mode):
            raise PermissionError('formal_evaluation_raw_grant')
    grant_path=directory/'evaluator-read-grant.json'
    fd=os.open(grant_path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        if os.fstat(stream.fileno()).st_size>2097152:
            raise ValueError('formal_evaluation_grant_capacity')
        grant=decode_json(stream.read(2097153))
    closure=capture.get('business_closure')
    if (type(closure) is not dict or closure.get('digest')!=digest_jcs({k:v for k,v in closure.items() if k!='digest'})
            or closure.get('intent_digest')!=intent['digest'] or closure.get('evidence_released') is not False
            or grant.get('kind')!=('PrivateEvaluatorReadGrant' if private else 'FormalEvaluatorReadGrant')
            or grant.get('digest')!=digest_jcs({k:v for k,v in grant.items() if k!='digest'})
            or grant.get('intent_digest')!=intent['digest'] or grant.get('runtime_capture_digest')!=capture['digest']
            or grant.get('business_closure_digest')!=closure['digest']
            or grant.get('custodian_uid' if private else 'controller_uid')!=raw_owner or grant.get('evaluator_gid')!=21004):
        raise ValueError('formal_evaluation_business_closure_or_grant')
    inventory={};total=0
    for path in paths:
        if path==grant_path or path.is_dir():continue
        info=path.lstat();total+=info.st_size
        if total>config['maximum_runtime_evidence_bytes']:
            raise ValueError('formal_evaluation_raw_byte_capacity')
        h=hashlib.sha256()
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        inventory[str(path.relative_to(directory))]={'digest':'sha256:'+h.hexdigest(),'bytes':info.st_size}
    if inventory!=grant.get('files') or total!=grant.get('total_bytes'):
        raise ValueError('formal_evaluation_raw_inventory_changed')
    observed=capture['result']
    if type(observed) is not dict:raise ValueError('formal_runtime_capture_incomplete')
    observed=dict(observed)
    trace_name=Path(observed['trace_path']).name
    expected_trace='run-'+digest_jcs(intent['binding']['body']['run_id'])[7:]+'.jsonl'
    if trace_name!=expected_trace:raise ValueError('formal_evaluation_trace_identity')
    observed['trace_path']=str(directory/'evidence'/trace_name)
    # Recount the actual native full contexts and final output using the locked
    # tokenizer; neither the Runtime's usage fields nor an Evaluator claim is a
    # substitute for the real local tokenizer/backend response pair.
    from skillloop.runtime.gateway import ExactLocalTokenizer
    from skillloop.runtime.adapter import tool_specs
    from skillloop.protocol import digest_bytes
    pins=config.get('tokenizer_hashes')
    model_root=Path('/model')
    if type(pins) is not dict or not pins or any(type(name) is not str or Path(name).name!=name for name in pins):
        raise ValueError('formal_evaluation_frozen_tokenizer_pins_required')
    actual={p.name:digest_bytes(p.read_bytes()) for p in model_root.iterdir() if p.is_file() and not p.is_symlink()}
    if actual!=pins or any(p.is_symlink() or p.is_dir() for p in model_root.iterdir()):
        raise ValueError('formal_evaluation_tokenizer_snapshot_changed')
    trace_events=[decode_json(line) for line in Path(observed['trace_path']).read_bytes().splitlines()]
    counter=ExactLocalTokenizer(str(model_root),expected_hashes=pins)
    try:
        models=[event for event in trace_events if event['type']=='model_response']
        if len(models)>16:raise ValueError('formal_evaluation_model_round_budget')
        tools=tool_specs(FamilyRegistry().profile(entry['profile']))
        overhead=config['ollama_template_overhead_tokens']
        if type(overhead) is not int or overhead<0:raise ValueError('formal_evaluation_template_overhead')
        for event in models:
            path=directory/'evidence'/'contexts'/event['context_digest'][7:]
            raw_context=path.read_bytes()
            if digest_bytes(raw_context)!=event['context_digest']:
                raise ValueError('formal_evaluation_native_context_changed')
            prompt=counter.count(decode_json(raw_context),tools,enable_thinking=False)+overhead
            response=event['response'];usage=response['usage'];backend=response['backend_response']
            if (event['preflight_prompt_tokens']!=prompt or usage['prompt_tokens']!=prompt
                    or backend['prompt_eval_count']!=prompt or backend['model']!=config['model_id']
                    or backend.get('message',{}).get('thinking') or response['model']!=config['model_id']
                    or type(usage['completion_tokens']) is not int or usage['completion_tokens']<0
                    or usage['completion_tokens']!=backend['eval_count'] or usage['reasoning_tokens']!=0
                    or usage['completion_tokens']>=config['max_output_tokens']
                    or prompt+config['max_output_tokens']>config['max_context_tokens']):
                raise ValueError('formal_evaluation_actual_native_token_usage')
        terminals=[event for event in trace_events if event['type']=='terminal']
        if len(terminals)!=1 or terminals[0].get('final_text')!=observed.get('final_text'):
            raise ValueError('formal_evaluation_terminal_trace_binding')
        final=observed.get('final_text')
        if final is not None:
            if not models or (models[-1]['response']['backend_response'].get('message',{}).get('content') or '')!=final:
                raise ValueError('formal_terminal_final_native_message_mismatch')
            final_tokens=counter.count_text(final)
            if final_tokens!=observed['final_text_tokens'] or final_tokens>config['max_output_tokens']:
                raise ValueError('formal_evaluation_final_output_capacity')
    finally:counter.close()
    store=PublicationSnapshot(snapshot_directory,epoch=config['deployment_epoch'],intent=intent,
        maximum_bytes=maximum_database_bytes)
    inference_attempts=store.inspect_inference_attempts(intent['binding']['body']['run_id'])
    from skillloop.runtime.gateway import OllamaGateway
    if [row['round_index'] for row in inference_attempts] != list(range(len(inference_attempts))):
        raise ValueError('formal_inference_attempt_frontier')
    if len(inference_attempts)>16 or len(inference_attempts)<len(models):
        raise ValueError('formal_inference_attempt_coverage')
    for index,event in enumerate(models):
        row=inference_attempts[index];reservation=decode_json(row['reservation_json']);request=reservation['request']
        context=decode_json((directory/'evidence'/'contexts'/event['context_digest'][7:]).read_bytes())
        backend=event['response']['backend_response']
        backend_raw=base64.b64decode(event['response']['backend_response_raw_b64'],validate=True)
        if (not 0<len(backend_raw)<=4194304 or decode_json(backend_raw)!=backend
                or digest_bytes(backend_raw)!=event['response']['backend_response_bytes_digest']):
            raise ValueError('formal_inference_original_response_bytes')
        native_payload={'model':config['model_id'],'messages':OllamaGateway._ollama_messages(context),
            'tools':tools,'stream':False,'think':False,'options':{'temperature':1.0,'top_p':0.95,
                'num_ctx':16384,'num_predict':2048}}
        if (reservation.get('kind')!='ProxyRuntimeInferenceReserved'
                or reservation.get('digest')!=digest_jcs({k:v for k,v in reservation.items() if k!='digest'})
                or request.get('digest')!=digest_jcs({k:v for k,v in request.items() if k!='digest'})
                or row['request_digest']!=request['digest'] or reservation['request_digest']!=request['digest']
                or request['run_request_digest']!=intent['run_request']['digest']
                or request['task_binding_digest']!=intent['binding']['digest']
                or request['deployment_epoch']!=config['deployment_epoch']
                or request['config_digest']!=digest_jcs(config)
                or request['campaign_id']!=intent['campaign_id']
                or request['run_id']!=intent['binding']['body']['run_id']
                or request['fencing_token']!=capture['lease']['body']['fencing_token']
                or request['payload_digest']!=digest_bytes(canonical_json_line(native_payload))
                or request['phase']!=('protected' if private else 'dev')
                or request['round_index']!=index or event['turn']!=index
                or request['messages_digest']!=digest_jcs(OllamaGateway._ollama_messages(context))
                or request['tools_digest']!=digest_jcs(tools)
                or request['input_tokens']!=event['preflight_prompt_tokens']
                or request['output_tokens']!=2048
                or request['model_identity']!={k:config[k] for k in ('model_id','model_manifest_digest','tokenizer_hashes')}
                or row['response_digest']!=digest_jcs(backend) or row['raw_response_digest']!=digest_bytes(backend_raw)
                or row['completed_at'] is None
                or reservation['redispatch_allowed'] is not False):
            raise ValueError('formal_inference_original_authority_binding')
    if len(inference_attempts)!=len(models) and observed['observation']['body']['evidence_complete']:
        raise ValueError('formal_inference_spent_or_unknown_not_complete')
    if store.manifest['approval_digest']!=capture['approval_digest']:
        raise ValueError('formal_evaluation_actual_approval_mismatch')
    if store.manifest['cancellation_fence']!=closure['cancellation']['body']['effective_fence']:
        raise ValueError('formal_evaluation_snapshot_closure_fence')
    from skillloop.protocol import digest_bytes
    terminal=store.inspect_terminal_output(intent['binding']['body']['run_id'])
    final=observed.get('final_text')
    if final is not None and type(final) is not str:raise ValueError('formal_terminal_output_shape')
    expected_output=digest_bytes((final if final is not None else '').encode('utf-8'))
    if terminal is None:
        if observed['observation']['body']['evidence_complete']:
            raise ValueError('formal_terminal_authority_record_missing')
    elif (terminal['raw_output_digest']!=expected_output
            or terminal['fence']!=capture['lease']['body']['fencing_token']):
        raise ValueError('formal_terminal_authority_record_mismatch')
    profile=FamilyRegistry().profile(entry['profile'])
    raw={k:base64.b64decode(v,validate=True) for k,v in intent['input_resources'].items()}
    inputs={slot:raw[rid] for slot,rid in profile['input_bindings'].items()}
    expected=build_artifact(entry['profile'],inputs)
    validate_artifact(entry['profile'],inputs,expected)
    if private:
        committed_inputs={name:base64.b64decode(raw,validate=True) for name,raw in entry['private_inputs'].items()}
        if inputs!=committed_inputs or digest_bytes(expected)!=entry['private_expected_digest']:
            raise ValueError('formal_private_evaluation_world_changed')
    case=compiled['cases'][entry['case_id']]
    result,events,summary,evidence=evaluate_run(case=case,objectives=compiled['objectives'],
        adapter_result=observed,store=store,expected=expected,notes=inputs['notes'],
        mutation_spec=compiled['mutations'].get(entry['case_id']))
    if (evidence['body']['trust_revision']!=capture['trust_revision']
            or result['body']['subject_digest']!=compiled['subject_digest']):
        raise ValueError('formal_evaluator_current_revision')
    from scripts.spec_v22_core import execution_record
    record=execution_record(intent['run_request'],result,evidence,intent['binding'])
    evaluation={'kind':'FormalTaskEvaluation','entry_digest':entry['digest'],'intent_digest':intent['digest'],
        'approval_digest':capture['approval_digest'],'trust_revision':capture['trust_revision'],
        'deployment_epoch':config['deployment_epoch'],
        'source_snapshot_digest':entry['source_admission']['source_snapshot']['digest'],
        'runtime_capture_digest':capture['digest'],'authority_snapshot_digest':store.manifest['digest'],
        'inference_attempts_digest':digest_jcs([{**row,'reservation_json':decode_json(row['reservation_json'])} for row in inference_attempts]),
        'run_request':intent['run_request'],'task_binding':intent['binding'],'result':result,
        'evidence_index':evidence,'execution_record':record,'trusted_events':events,'summary':summary,
        'evaluator_uid':21004,'independent_gate_complete':False,'qualification_issued':False}
    evaluation['digest']=digest_jcs(evaluation)
    if review_only:return evaluation
    output=Path(output_directory)
    info=output.lstat()
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21004 or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('formal_evaluator_output_grant')
    fd=os.open(output/(intent['digest'][7:]+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o640)
        stream.write(canonical_json_line(evaluation));stream.flush();os.fsync(stream.fileno())
    directory_fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory_fd)
    finally:os.close(directory_fd)
    return evaluation


def main():
    """Actual evaluator entry; protected assignments are Evaluator-owned."""
    if os.geteuid()!=21004:raise PermissionError('formal_evaluator_uid_required')
    os.umask(0o077)
    path=Path(os.environ['SKILLLOOP_EVALUATOR_ASSIGNMENT'])
    parent=path.parent.lstat()
    assignment_owner=parent.st_uid
    if assignment_owner not in {21001,21004}:raise PermissionError('formal_evaluator_assignment_role')
    if (not path.is_absolute() or path.parent.is_symlink() or parent.st_uid!=assignment_owner
            or parent.st_gid!=21004 or stat.S_IMODE(parent.st_mode)!=0o750):
        raise PermissionError('formal_evaluator_assignment_directory')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=assignment_owner or info.st_gid!=21004
                or stat.S_IMODE(info.st_mode)!=0o640 or info.st_size>8388608):
            raise PermissionError('formal_evaluator_assignment_custody')
        assignment=decode_json(stream.read(8388609))
    required={'kind','entry','intent','capture','maximum_database_bytes','snapshot_wait_seconds','campaign_deadline','digest'}
    if (type(assignment) is not dict or set(assignment)!=required
            or assignment['kind']!='FormalEvaluatorAssignment'
            or assignment['digest']!=digest_jcs({k:v for k,v in assignment.items() if k!='digest'})):
        raise ValueError('formal_evaluator_assignment_identity')
    if assignment_owner!=(21004 if assignment['entry'].get('kind')=='protected' else 21001):
        raise PermissionError('formal_evaluator_private_assignment_custody')
    wait=assignment['snapshot_wait_seconds']
    deadline=datetime.fromisoformat(assignment['campaign_deadline'].replace('Z','+00:00'))
    if type(wait) is not int or not 1<=wait<=60 or deadline.tzinfo is None:
        raise ValueError('formal_evaluator_snapshot_original_budget')
    intent=assignment['intent']
    if (type(intent) is not dict or type(intent.get('digest')) is not str
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',intent['digest'])
            or intent['digest']!=digest_jcs({k:v for k,v in intent.items() if k!='digest'})):
        raise ValueError('formal_evaluator_snapshot_intent')
    snapshot=Path('/authority')/intent['digest'][7:]
    started=time.monotonic()
    while not os.path.lexists(snapshot/'snapshot.json'):
        if time.monotonic()-started>=wait or datetime.now(timezone.utc)>=deadline:
            raise TimeoutError('formal_evaluator_snapshot_not_committed')
        time.sleep(0.2)
    evaluate_capture(entry=assignment['entry'],intent=assignment['intent'],capture=assignment['capture'],
        run_directory=Path('/raw'),snapshot_directory=snapshot,output_directory=Path('/evaluation'),
        maximum_database_bytes=assignment['maximum_database_bytes'])


if __name__=='__main__':main()
