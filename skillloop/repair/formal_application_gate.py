"""Gate rederives a bounded application from the real patcher role's output.

This grants only candidate application provenance. Scanning, development
pairing, finalist freeze, private evaluation and qualification remain separate.
"""
import base64
from datetime import datetime,timezone
import os
from pathlib import Path
import stat

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line,decode_json,digest_bytes,digest_jcs,validate_envelope
from skillloop.repair.applicator import apply_proposal,bundle
from skillloop.repair.proposal import patch_messages,parse_body_response
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.round_manifest import read_round_manifest


def _patcher_document(directory,name,limit=8388608):
    root=Path(directory);parent=root.lstat()
    if (not root.is_absolute() or root.is_symlink() or parent.st_uid!=21007
            or parent.st_gid!=21001 or stat.S_IMODE(parent.st_mode)!=0o750):
        raise PermissionError('application_gate_actual_patcher_directory')
    fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21007 or info.st_gid!=21001
                or stat.S_IMODE(info.st_mode)!=0o640 or info.st_size>limit):
            raise PermissionError('application_gate_actual_patcher_file')
        raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('application_gate_patcher_file_capacity')
    return decode_json(raw)


def review_application(*,assignment_path,patcher_directory,tokenizer_path,
                       whole_round_manifest_path,output_directory):
    if os.geteuid()!=21005 or 21001 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('application_gate_actual_role')
    job=read_owned(assignment_path,uid=21001,gid=21005,limit=8388608)
    fields={'kind','campaign_id','config_digest','whole_round_manifest_digest',
            'patcher_assignment','file_set','history','parent_policy','repair_round','deadline','digest'}
    if (set(job)!=fields or job['kind']!='FormalCandidateApplicationAssignment'
            or type(job['repair_round']) is not int or not 1<=job['repair_round']<=2
            or type(job['history']) is not list or len(job['history'])!=job['repair_round']-1):
        raise ValueError('application_gate_assignment')
    whole=read_round_manifest(whole_round_manifest_path)
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==job['campaign_id']),None)
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
    if (whole['digest']!=job['whole_round_manifest_digest'] or scope is None
            or deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline):
        raise ValueError('application_gate_original_whole_round')
    assignment=job['patcher_assignment']
    if (assignment.get('digest')!=digest_jcs({k:v for k,v in assignment.items() if k!='digest'})
            or assignment.get('kind')!='FormalNativeProposalAssignment'
            or assignment.get('role_uid')!=21007 or assignment.get('profile')!=scope['profile']
            or assignment.get('finding') is not None or type(assignment.get('diagnosis')) is not dict):
        raise ValueError('application_gate_actual_assignment_binding')
    proposal=read_owned(Path(patcher_directory)/'proposal.json',uid=21007,gid=21001,limit=8388608)
    policy=read_owned(Path(patcher_directory)/'session-policy.json',uid=21007,gid=21001,limit=262144)
    # A completed proposal cannot hide a second request or an unknown response
    # in the same reserved session. No old or partial session is eligible here.
    expected_files={'proposal.json','session-policy.json','request-0.json','response-0.json','spending.lock'}
    with os.scandir(patcher_directory) as entries:
        names=set()
        for entry in entries:
            names.add(entry.name)
            if entry.name not in expected_files or not entry.is_file(follow_symlinks=False):
                raise ValueError('application_gate_incomplete_or_extra_native_attempt')
    if names!=expected_files:raise ValueError('application_gate_complete_single_native_session_required')
    if (proposal.get('kind')!='FormalNativePatchProposal' or proposal.get('producer_uid')!=21007
            or proposal.get('assignment_digest')!=assignment['digest']
            or proposal.get('policy_digest')!=policy['digest']
            or assignment.get('policy_digest')!=policy['digest']
            or proposal.get('whole_round_manifest_digest')!=whole['digest']
            or proposal.get('qualification_issued') is not False
            or policy.get('kind')!='NativeProposalPolicy' or policy.get('role_uid')!=21007
            or policy.get('max_requests')!=1 or policy.get('campaign_deadline')!=job['deadline']
            or policy.get('whole_round_manifest_digest')!=whole['digest']
            or policy.get('source_digest')!=whole['source_digest']):
        raise ValueError('application_gate_actual_native_provenance')
    from scripts.dgx_m6_repair import source_index
    if digest_jcs(source_index(Path(__file__).resolve().parents[2]))!=whole['source_digest']:
        raise ValueError('application_gate_current_source_changed')
    files=job['file_set'];parent=bundle(files['files'],job['parent_policy'],
        files['obligation_digest'],files['compiler_digest'])
    skill=base64.b64decode(assignment['skill_b64'],validate=True)
    if (files['subject_digest']!=parent['digest'] or assignment['parent_subject_digest']!=parent['digest']
            or skill!=files['files']['SKILL.md'].encode('utf-8')):
        raise ValueError('application_gate_exact_parent_package')
    request=_patcher_document(patcher_directory,'request-0.json')
    response=_patcher_document(patcher_directory,'response-0.json')
    messages=patch_messages(profile=scope['profile'],skill_bytes=skill,diagnosis=assignment['diagnosis'])
    if (request.get('kind')!='NativeProposalIntent' or request.get('slot')!=0
            or request.get('policy_digest')!=policy['digest'] or request.get('messages')!=messages
            or response.get('policy_digest')!=policy['digest'] or response.get('spent') is not True):
        raise ValueError('application_gate_original_native_request_response')
    model=policy['model_config']
    if (model.get('max_context_tokens')!=16384 or model.get('max_output_tokens')!=1024
            or model.get('temperature')!=0.2 or model.get('top_p')!=0.9
            or model.get('thinking') is not False or model.get('gateway_uid')!=21011):
        raise ValueError('application_gate_frozen_patcher_parameters')
    tokenizer=ExactLocalTokenizer(tokenizer_path,expected_hashes=policy['tokenizer_hashes'])
    try:
        prompt=tokenizer.count(messages,[],enable_thinking=False)+model['template_overhead_tokens']
    finally:tokenizer.close()
    completion=response['response'];backend=completion['backend_response'];usage=completion['usage']
    if (prompt+1024>16384 or response.get('actual_prompt_tokens')!=prompt
            or backend.get('model')!=model['model'] or backend.get('done_reason')!='stop'
            or backend.get('prompt_eval_count')!=prompt
            or backend.get('message',{}).get('thinking')
            or backend.get('message',{}).get('tool_calls')
            or type(backend.get('eval_count')) is not int or not 0<=backend['eval_count']<=1024
            or usage!={'prompt_tokens':prompt,'completion_tokens':backend['eval_count'],
                      'total_tokens':prompt+backend['eval_count'],'reasoning_tokens':0}
            or completion['choices'][0]['message']['content']!=backend['message']['content']):
        raise ValueError('application_gate_actual_native_token_and_message_identity')
    rebuilt,evidence,raw=parse_body_response(raw=canonical_json_line(completion),messages=messages,
        skill_bytes=skill,parent_subject_digest=parent['digest'],diagnosis=assignment['diagnosis'],
        expected_model=model['model'],patcher_config=model)
    if (rebuilt!=proposal['proposal'] or evidence!=proposal['proposal_evidence']
            or digest_bytes(raw)!=proposal['raw_response_digest']):
        raise ValueError('application_gate_model_proposal_reconstruction')
    applied=apply_proposal(rebuilt,files,job['history'],job['parent_policy'])
    validate_envelope(applied['candidate_bundle'])
    if datetime.now(timezone.utc)>=deadline:raise TimeoutError('application_gate_original_clock_exhausted')
    result={'kind':'GateBoundedCandidateApplication','campaign_id':job['campaign_id'],
        'deployment_epoch':whole['deployment_epoch'],'config_digest':job['config_digest'],
        'parent_subject_digest':parent['digest'],'candidate_bundle_digest':applied['candidate_subject_digest'],
        'package_digest':applied['candidate_bundle']['body']['skill_digest'],
        'assignment_digest':job['digest'],'proposal_output_digest':proposal['digest'],
        'application_digest':digest_jcs(applied),'application_verified':True,
        'repair_round':job['repair_round'],'qualification_issued':False,
        'development_pairing_verified':False,'source_admission_issued':False,
        'review_completed_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
    result['digest']=digest_jcs(result)
    output=Path(output_directory);info=output.lstat()
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21005 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('application_gate_output_custody')
    fd=os.open(output/(job['digest'][7:]+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,21001);os.fchmod(stream.fileno(),0o640)
        stream.write(canonical_json_line(result));stream.flush();os.fsync(stream.fileno())
    from skillloop.protection.current_task import _publish
    artifact={'kind':'GateAppliedCandidate','campaign_id':job['campaign_id'],
        'review_digest':result['digest'],'application':applied,'qualification_issued':False}
    artifact['digest']=digest_jcs(artifact)
    _publish(output/(job['digest'][7:]+'.application.json'),artifact,21001)
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return result


def main():
    os.umask(0o077)
    review_application(assignment_path='/assignment/job.json',patcher_directory='/patcher',
        tokenizer_path='/model',whole_round_manifest_path='/whole-round/manifest.json',
        output_directory='/reviews')


if __name__=='__main__':main()
