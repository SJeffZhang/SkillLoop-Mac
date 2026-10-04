"""Isolated formal generator/patcher entry; proposals never authorize effects."""
import base64
import os
from pathlib import Path
import stat
import sys

from skillloop.protocol import canonical_json_line, digest_bytes, digest_jcs
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.runtime.gateway import ExactLocalTokenizer, OllamaGateway
from skillloop.runtime.native_proposals import NativeProposalSession
from skillloop.runtime.round_manifest import read_round_manifest


def execute():
    uid=os.geteuid()
    if uid not in {21006,21007} or 21001 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('formal_proposal_actual_role')
    job=read_owned('/assignment/job.json',uid=21001,gid=uid,limit=2097152)
    policy=read_owned('/assignment/policy.json',uid=21001,gid=uid,limit=262144)
    required={'kind','role_uid','policy_digest','profile','skill_b64','finding','parent_subject_digest','diagnosis','digest'}
    if (set(job)!=required or job['kind']!='FormalNativeProposalAssignment'
            or job['role_uid']!=uid or job['policy_digest']!=policy['digest']
            or job['profile'] not in {'orders_total','refunds_total','markdown_index'}):
        raise ValueError('formal_proposal_assignment_binding')
    whole=read_round_manifest('/whole-round/manifest.json')
    if whole['digest']!=policy['whole_round_manifest_digest'] or whole['source_digest']!=policy['source_digest']:
        raise ValueError('formal_proposal_whole_round_binding')
    skill=base64.b64decode(job['skill_b64'],validate=True)
    if not 1<=len(skill)<=4096:raise ValueError('formal_proposal_instruction_capacity')
    if uid==21006 and (job['parent_subject_digest'] is not None or job['diagnosis'] is not None):
        raise ValueError('formal_generator_unrelated_input')
    if uid==21007 and (job['finding'] is not None or type(job['diagnosis']) is not dict):
        raise ValueError('formal_patcher_diagnosis_input')
    tokenizer=ExactLocalTokenizer('/model',expected_hashes=policy['tokenizer_hashes'])
    try:
        model=policy['model_config']
        gateway=OllamaGateway('http://127.0.0.1:11434',tokenizer,model=model['model'],
            template_overhead_tokens=model['template_overhead_tokens'],
            max_context_tokens=model['max_context_tokens'],max_output_tokens=model['max_output_tokens'],
            timeout_seconds=policy['request_timeout_seconds'],unix_socket_path='/model-bridge/model.sock',
            expected_server_uid=21011,temperature=model['temperature'],top_p=model['top_p'])
        session=NativeProposalSession(policy_path='/assignment/policy.json',gateway=gateway,
                                     evidence_directory='/evidence')
        if uid==21006:
            from skillloop.discovery.llm_attack import propose_payload
            payload,evidence=propose_payload(job['profile'],job['finding'],skill,native_session=session)
            value={'kind':'FormalNativeAttackProposal','payload_b64':base64.b64encode(payload).decode(),
                   'payload_digest':digest_bytes(payload),'proposal_evidence':evidence}
        else:
            from skillloop.repair.proposal import propose_body
            proposal,evidence,raw=propose_body(profile=job['profile'],skill_bytes=skill,
                parent_subject_digest=job['parent_subject_digest'],diagnosis=job['diagnosis'],native_session=session)
            value={'kind':'FormalNativePatchProposal','proposal':proposal,'proposal_evidence':evidence,
                   'raw_response_digest':digest_bytes(raw)}
        value.update(assignment_digest=job['digest'],policy_digest=policy['digest'],producer_uid=uid,
                     whole_round_manifest_digest=whole['digest'],qualification_issued=False)
        value['digest']=digest_jcs(value)
        session._save(Path('/evidence/proposal.json'),value)
        return value
    finally:tokenizer.close()


def grant_preserved_evidence():
    root=Path('/evidence');uid=os.geteuid();paths=[]
    if root.is_symlink() or root.lstat().st_uid!=uid:
        raise PermissionError('formal_proposal_evidence_custody')
    for parent,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            path=Path(parent)/name;info=path.lstat()
            if (path.is_symlink() or info.st_uid!=uid
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
                raise PermissionError('formal_proposal_evidence_custody')
            paths.append(path)
            if len(paths)>512:raise ValueError('formal_proposal_evidence_inventory_capacity')
    # Only after the native call/proposal has ended, grant the trusted Controller
    # access for complete export and independent review. No Runtime/private role.
    for path in paths+[root]:
        os.chown(path,-1,21001);os.chmod(path,0o750 if path.is_dir() else 0o640)
        if path.is_file():
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def main():
    os.umask(0o077)
    try:execute()
    finally:
        primary=sys.exc_info()[1]
        try:grant_preserved_evidence()
        except BaseException as error:
            if primary is None:raise
            primary.add_note('formal_proposal_evidence_grant_error:'+type(error).__name__)


if __name__=='__main__':main()
