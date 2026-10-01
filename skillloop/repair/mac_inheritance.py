"""Verify archived repair applications without regenerating their proposals."""
import json
from pathlib import Path
from skillloop.protocol import digest_bytes,digest_jcs,decode_json,validate_envelope
from skillloop.repair.applicator import apply_proposal,bundle
from skillloop.families.fixtures import load_example_skill
from scripts.spec_v22_core import validate_suite

def verify_inherited_candidate(root:Path,profile:str)->dict:
    def read(path):return json.loads(path.read_text())
    if (root/'chained-repair.json').exists():
        chain=read(root/'chained-repair.json')
        if chain['digest']!=digest_jcs({k:v for k,v in chain.items() if k!='digest'}):raise ValueError('repair_chain_digest')
        parent=Path(chain['parent_ref'])
        if parent.resolve()==root.resolve() or (parent/'chained-repair.json').exists():raise ValueError('repair_chain_round_limit')
        inherited=verify_inherited_candidate(parent,profile)
        original=read(parent/'manifest.json');info=original['subjects'][profile]
        first=read(parent/info['applied_proposal']/'application.json')
        fs=read(parent/profile/'file-set.json')
        current={'files':first['files'],'subject_digest':first['candidate_subject_digest'],'policies':{},**{k:fs[k] for k in ('obligation_digest','compiler_digest')}}
        proposal=validate_envelope(read(root/'second-proposal.json'))
        application=apply_proposal(proposal,current,[first['history_entry']],first['policy'])
        if application!=read(root/'second-application.json') or load_example_skill(profile,root=root/'candidate')!=application['files']['SKILL.md'].encode():raise ValueError('repair_chain_application')
        compiled=read(parent/profile/'compiled.json');compiled.update(subject_digest=application['candidate_subject_digest'],skill_digest=digest_bytes(application['files']['SKILL.md'].encode()))
        if compiled!=read(root/profile/'compiled.json'):raise ValueError('repair_chain_suite')
        expected=original.copy();expected['subjects']=dict(original['subjects']);expected['subjects'][profile]={**info,'generated_proposals':info['generated_proposals']+1,'repair_round':2,'candidate_bundle':application['candidate_bundle']}
        if expected!=read(root/'manifest.json') or chain['parent_proof_digest']!=digest_jcs(inherited):raise ValueError('repair_chain_manifest')
        return {**inherited,'scope':'explicit_second_round_local_patch','manifest_digest':digest_jcs(expected),'application_digest':digest_jcs(application),'proposal_digest':proposal['digest'],'candidate_subject_digest':application['candidate_subject_digest'],'repair_chain_digest':chain['digest'],'repair_rounds':2}
    manifest=read(root/'manifest.json');info=manifest['subjects'][profile]
    if info.get('status')!='applied' or info.get('repair_round',1)!=1 or info.get('parent_output'):
        raise ValueError('inherited_repair_scope_requires_explicit_chain')
    relative=Path(info['applied_proposal'])
    if relative.is_absolute() or '..' in relative.parts:raise ValueError('unsafe_proposal_path')
    directory=root/profile;proposal_root=root/relative
    files=read(directory/'file-set.json');policy=read(directory/'parent-policy.json')
    proposal=validate_envelope(read(proposal_root/'proposal.json'))
    application=apply_proposal(proposal,files,[],policy)
    if application!=read(proposal_root/'application.json') or application['candidate_bundle']!=info['candidate_bundle']:
        raise ValueError('inherited_application_recompute')
    actual=load_example_skill(profile,root=root/'candidate')
    if actual!=application['files']['SKILL.md'].encode():raise ValueError('inherited_candidate_bytes_changed')
    compiled=read(directory/'compiled.json')
    validate_suite(compiled['suite'],list(compiled['cases'].values()),compiled['objectives'])
    if compiled['subject_digest']!=application['candidate_subject_digest'] or compiled['skill_digest']!=digest_bytes(actual):
        raise ValueError('inherited_subject_binding')
    fixed=info['fixed']
    submitted=bundle(files['files'],policy,**fixed)
    if submitted!=info['submitted_bundle']:raise ValueError('inherited_submitted_binding')
    raw=(proposal_root/'response.bin').read_bytes();response=decode_json(raw)
    evidence=read(proposal_root/'evidence.json');body=decode_json(response['choices'][0]['message']['content'].encode())
    if (evidence['response_digest']!=digest_bytes(raw) or evidence['proposal_digest']!=proposal['digest']
        or body!={'replacement_body':proposal['body']['edits'][0]['replacement_utf8']}
        or response.get('usage',{}).get('reasoning_tokens')!=0):raise ValueError('inherited_raw_proposal_binding')
    snapshot=read(directory/'history-snapshot.json')
    if {row['digest'] for row in snapshot}!={row['history_digest'] for row in info['history_bindings']}:
        raise ValueError('inherited_history_snapshot_binding')
    baseline=root.parent/'m5b-a30'
    accepted=read(baseline/'m5b-gate.json')
    if (accepted['digest']!=manifest['baseline_gate_digest'] or
        accepted['digest']!=digest_jcs({k:v for k,v in accepted.items() if k!='digest'})):
        raise ValueError('inherited_baseline_acceptance_binding')
    # Recompile historical cases with their original tokenizer identity. The
    # new native tokenizer is reserved for new Mac runtime evidence.
    from transformers import AutoTokenizer
    from scripts.dgx_m5b_gate import _compile_subject
    from scripts.dgx_m6_repair import append_history
    legacy_tokenizer=AutoTokenizer.from_pretrained(str(root.parent/'model-cache/Qwen3.8-27B-FP8'),local_files_only=True,trust_remote_code=True)
    class LegacyCounter:
        def count_text(self,text):return len(legacy_tokenizer.encode(text,add_special_tokens=False))
    scans=read(root.parent/'platform/m5b-pilot-scan-2/scan-index.json')
    rebuilt,*_=_compile_subject(profile,scans['subjects'][profile],baseline,LegacyCounter())
    rebuilt,bindings=append_history(rebuilt,snapshot)
    rebuilt.update(skill_digest=digest_bytes(actual),subject_digest=application['candidate_subject_digest'])
    if rebuilt!=compiled or bindings!=info['history_bindings']:
        raise ValueError('inherited_suite_recompile')
    source=root.parent/Path(manifest['source_ref']).name
    for relative,digest in manifest['source_index'].items():
        if digest_bytes((source/relative).read_bytes())!=digest:raise ValueError('inherited_source_binding:'+relative)
    return {'scope':'archived_application_and_inputs_not_new_model_acceptance','profile':profile,
        'manifest_digest':digest_jcs(manifest),'application_digest':digest_jcs(application),'proposal_digest':proposal['digest'],
        'compiled_digest':digest_jcs(compiled),'candidate_subject_digest':application['candidate_subject_digest'],
        'submitted_subject_digest':submitted['digest'],'history_snapshot_digest':digest_jcs(snapshot),'new_model_calls':0}
