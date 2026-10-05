"""Independent reconstruction of an original Generator native attempt."""
import base64,math,os,re
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.discovery.llm_attack import attack_messages,parse_payload_response
from skillloop.discovery.raw_evidence import read_granted_raw
from skillloop.protocol import canonical_json_line,decode_json,digest_bytes,digest_jcs


def review_generator(directory,*,assignment,finding,skill,profile,whole,deadline,tokenizer,raw_sink):
    if os.geteuid()!=21005:raise PermissionError('generator_review_actual_gate')
    if (assignment.get('digest')!=digest_jcs({k:v for k,v in assignment.items() if k!='digest'})
            or assignment.get('kind')!='FormalNativeProposalAssignment' or assignment.get('role_uid')!=21006
            or assignment.get('profile')!=profile or assignment.get('finding')!=finding
            or assignment.get('parent_subject_digest') is not None or assignment.get('diagnosis') is not None
            or base64.b64decode(assignment['skill_b64'],validate=True)!=skill):
        raise ValueError('generator_review_actual_source_finding_assignment')
    root=Path(directory)
    expected={'proposal.json','session-policy.json','request-0.json','response-0.json','spending.lock'}
    if {p.name for p in root.iterdir()}!=expected:
        raise ValueError('generator_review_complete_original_single_attempt')
    records={};originals=[]
    for name,limit in (('proposal.json',8388608),('session-policy.json',262144),
                       ('request-0.json',8388608),('response-0.json',8388608)):
        value=read_owned(root/name,uid=21006,gid=21001,limit=limit)
        records[name]=value;originals.append({'path':root/name,'uid':21006,'gid':21001,'limit':limit,'value':value})
    # Lock is original custody, never an additional request or evidence result.
    lock=read_granted_raw(root/'spending.lock',uid=21006,gid=21001,limit=4096)
    originals.append({'path':root/'spending.lock','uid':21006,'gid':21001,'limit':4096,'bytes_digest':digest_bytes(lock)})
    if lock:raise ValueError('generator_review_original_spending_lock')
    proposal,policy,request,response=(records[n] for n in ('proposal.json','session-policy.json','request-0.json','response-0.json'))
    messages=attack_messages(profile,finding,skill)
    model=policy['model_config'];timeout=policy['request_timeout_seconds'];latency=response.get('latency_seconds')
    grant=request.get('inference_grant_digest')
    if (policy.get('kind')!='NativeProposalPolicy' or policy.get('role_uid')!=21006 or policy.get('max_requests')!=1
            or policy.get('campaign_deadline')!=deadline or policy.get('whole_round_manifest_digest')!=whole['digest']
            or policy.get('source_digest')!=whole['source_digest'] or policy.get('tokenizer_hashes')!=tokenizer.snapshot_hashes
            or type(timeout) is not int or not 1<=timeout<=180
            or model.get('max_context_tokens')!=16384 or model.get('max_output_tokens')!=512
            or model.get('temperature')!=0.7 or model.get('top_p')!=0.9
            or model.get('thinking') is not False or model.get('gateway_uid')!=21011
            or request.get('kind')!='NativeProposalIntent' or type(request.get('slot')) is not int or request.get('slot')!=0
            or request.get('policy_digest')!=policy['digest'] or request.get('messages')!=messages
            or request.get('reserved_input_tokens')!=15872 or request.get('reserved_output_tokens')!=512
            or request.get('reserved_seconds')!=timeout
            or type(grant) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',grant)
            or response.get('kind')!='NativeProposalResponse' or type(response.get('slot')) is not int or response.get('slot')!=0
            or response.get('policy_digest')!=policy['digest'] or response.get('inference_grant_digest')!=grant
            or response.get('spent') is not True or type(latency) not in (int,float)
            or not math.isfinite(latency) or not 0<=latency<=timeout):
        raise ValueError('generator_review_original_request_policy_and_budget')
    completion=response['response'];backend=completion['backend_response']
    raw=base64.b64decode(completion['backend_response_raw_b64'],validate=True)
    prompt=tokenizer.count(messages,[],enable_thinking=False)+model['template_overhead_tokens']
    count=backend.get('eval_count')
    if (not 1<=len(raw)<=4194304 or decode_json(raw)!=backend
            or digest_bytes(raw)!=completion.get('backend_response_bytes_digest')
            or prompt+512>16384 or type(response.get('actual_prompt_tokens')) is not int
            or response['actual_prompt_tokens']!=prompt or backend.get('model')!=model['model']
            or backend.get('done') is not True or backend.get('done_reason')!='stop'
            or type(backend.get('prompt_eval_count')) is not int or backend['prompt_eval_count']!=prompt
            or backend.get('message',{}).get('thinking') or backend.get('message',{}).get('tool_calls')
            or type(count) is not int or not 0<=count<=512
            or completion.get('usage')!={'prompt_tokens':prompt,'completion_tokens':count,'total_tokens':prompt+count,'reasoning_tokens':0}
            or completion['choices'][0]['message']['content']!=backend['message']['content']):
        raise ValueError('generator_review_actual_raw_tokens_and_message')
    payload,evidence=parse_payload_response(canonical_json_line(completion),messages=messages,
        finding=finding,expected_model=model['model'],generator_config=model)
    if (proposal.get('kind')!='FormalNativeAttackProposal' or proposal.get('producer_uid')!=21006
            or proposal.get('assignment_digest')!=assignment['digest'] or assignment.get('policy_digest')!=policy['digest']
            or proposal.get('policy_digest')!=policy['digest'] or proposal.get('inference_grant_digest')!=grant
            or proposal.get('whole_round_manifest_digest')!=whole['digest'] or proposal.get('qualification_issued') is not False
            or base64.b64decode(proposal['payload_b64'],validate=True)!=payload
            or proposal.get('payload_digest')!=digest_bytes(payload) or proposal.get('proposal_evidence')!=evidence):
        raise ValueError('generator_review_reconstructed_proposal_mismatch')
    raw_sink(originals)
    return payload,evidence['generator_config_digest'],proposal['digest']
