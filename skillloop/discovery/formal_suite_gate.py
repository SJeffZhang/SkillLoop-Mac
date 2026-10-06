"""Gate produces development cases from current semantic and native evidence."""
import base64,os
from datetime import datetime,timezone
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.discovery.semantic_review import review_semantic
from skillloop.discovery.generator_review import review_generator
from skillloop.discovery.finding_suite import compile_finding_campaign
from skillloop.discovery.suite import compile_dev_suite
from skillloop.discovery.raw_evidence import preserve_reviewed_raw
from skillloop.loader import validate_source_admission
from skillloop.protocol import digest_bytes,digest_jcs,canonical_json_line
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.round_manifest import read_round_manifest


def produce_discovery_suite(assignment_path,*,output_directory,tokenizer_path,whole_round_manifest_path):
    if os.geteuid()!=21005 or not {21001,21003}.issubset(set(os.getgroups())|{os.getegid()}):
        raise PermissionError('discovery_suite_actual_gate_custody')
    job=read_owned(assignment_path,uid=21001,gid=21005,limit=8388608)
    fields={'kind','campaign_id','config','deadline','whole_round_manifest_digest',
        'source_grant_path','semantic_directory','generator_inputs','tokenizer_hashes','digest'}
    if set(job)!=fields or job['kind']!='FormalDiscoverySuiteAssignment':
        raise ValueError('discovery_suite_original_assignment')
    whole=read_round_manifest(whole_round_manifest_path)
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==job['campaign_id']),None)
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'));config=job['config']
    if (scope is None or whole['digest']!=job['whole_round_manifest_digest'] or deadline.tzinfo is None
            or datetime.now(timezone.utc)>=deadline or config.get('whole_flow_required') is not True
            or config.get('deployment_epoch')!=whole['deployment_epoch'] or config.get('mac_runtime_image')!=whole['image']):
        raise ValueError('discovery_suite_original_whole_campaign')
    from skillloop.runtime.whole_source import whole_source_index
    if digest_jcs(whole_source_index(Path(__file__).resolve().parents[2]))!=whole['source_digest']:
        raise ValueError('discovery_suite_actual_source_changed')
    grant=read_owned(job['source_grant_path'],uid=21010,gid=21003,limit=2097152)
    if (grant.get('kind')!='AdminCampaignSourceAdmission' or grant.get('campaign_id')!=job['campaign_id']
            or grant.get('config')!=config or grant.get('deployment_epoch')!=whole['deployment_epoch']):
        raise ValueError('discovery_suite_current_source_grant')
    admission=grant['admission'];validate_source_admission(admission,config,grant['subject_digest'])
    snapshot=admission['source_snapshot']
    semantic_job=read_owned(Path(job['semantic_directory'])/'assignment.json',uid=21011,gid=21001,limit=2097152)
    if (semantic_job.get('campaign_digest')!=job['campaign_id']
            or semantic_job['model_policy'].get('campaign_deadline')!=job['deadline']
            or semantic_job['model_policy'].get('tokenizer_hashes')!=job['tokenizer_hashes']):
        raise ValueError('discovery_suite_same_campaign_tokenizer_and_clock')
    originals=[{'path':assignment_path,'uid':21001,'gid':21005,'limit':8388608,'value':job},
        {'path':job['source_grant_path'],'uid':21010,'gid':21003,'limit':2097152,'value':grant}]
    def preserve(rows):originals.extend(rows)
    report,findings,semantic=review_semantic(job['semantic_directory'],snapshot=snapshot,
        profile=scope['profile'],whole=whole,raw_sink=preserve)
    applicable={f['digest']:f for f in findings if f['body']['dynamic_applicability']=='applicable'}
    # Unmapped multi-objective findings require an explicit contract decision;
    # silently omitting them cannot produce a complete development matrix.
    if any(len(f['body']['objective_ids'])!=1 for f in applicable.values()):
        raise ValueError('discovery_suite_finding_needs_contract')
    rows=job['generator_inputs']
    if (type(rows) is not list or len(rows)>16 or any(type(r) is not dict or set(r)!=
            {'finding_digest','assignment','evidence_directory'} for r in rows)
            or len({r['finding_digest'] for r in rows})!=len(rows)
            or {r['finding_digest'] for r in rows}!=set(applicable)):
        raise ValueError('discovery_suite_all_applicable_findings_required')
    skill=base64.b64decode(admission['package_files']['SKILL.md'],validate=True)
    tokenizer=ExactLocalTokenizer(tokenizer_path,expected_hashes=job['tokenizer_hashes'])
    reviewed=[];inputs=[]
    try:
        for row in rows:
            finding=applicable[row['finding_digest']]
            payload,model_config,proposal=review_generator(row['evidence_directory'],assignment=row['assignment'],
                finding=finding,skill=skill,profile=scope['profile'],whole=whole,deadline=job['deadline'],
                tokenizer=tokenizer,raw_sink=preserve)
            reviewed.append({'finding_digest':finding['digest'],'proposal_digest':proposal})
            inputs.append({'finding':finding,'llm_payload':payload,'generator_config_digest':model_config})
        compiled,plans=(compile_finding_campaign(scope['profile'],inputs,count_tokens=tokenizer.count_text,
            campaign_id=job['campaign_id'],config=config,subject_digest=grant['subject_digest']) if inputs else (compile_dev_suite(scope['profile']),{}))
    finally:tokenizer.close()
    compiled={**compiled,'subject_digest':grant['subject_digest'],'skill_digest':digest_bytes(skill)}
    raw=preserve_reviewed_raw(output_directory,originals,
        maximum_bytes=int(os.environ['SKILLLOOP_RAW_HISTORY_MAX_BYTES']))
    if datetime.now(timezone.utc)>=deadline:raise TimeoutError('discovery_suite_original_clock_exhausted')
    value={'kind':'GateProducedDevelopmentSuite','campaign_id':job['campaign_id'],
        'deployment_epoch':whole['deployment_epoch'],'config_digest':digest_jcs(config),
        'whole_round_manifest_digest':whole['digest'],'assignment_digest':job['digest'],
        'source_grant_digest':grant['digest'],'scanner_report':report,'findings':findings,
        'semantic_evidence_digest':semantic,'generator_reviews':reviewed,
        'compiled':compiled,'attack_plans':plans,'reviewed_raw_inputs':raw,
        'all_attempt_history_complete':False,'qualification_issued':False}
    value['digest']=digest_jcs(value)
    if len(canonical_json_line(value))>8388608:raise ValueError('discovery_suite_output_capacity')
    output=_directory(output_directory,21005,21001,0o750)
    _publish(output/'compiled.json',value,21001)
    return value


def main():
    os.umask(0o077)
    return produce_discovery_suite('/assignment/job.json',output_directory='/suite',tokenizer_path='/model',
        whole_round_manifest_path='/whole-round/manifest.json')


if __name__=='__main__':main()
