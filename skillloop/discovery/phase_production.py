"""Actual Admin production of every required public development task unit."""
import base64
from datetime import datetime,timezone
import os
from pathlib import Path

from scripts.spec_v22_core import validate_plan,validate_suite
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.families.fixtures import load_clean_fixture
from skillloop.families.registry import FAMILY_SPEC,FamilyRegistry
from skillloop.loader import validate_source_admission
from skillloop.protocol import canonical_json_line,digest_bytes,digest_jcs
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.mac_entry import verify_formal_entry
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.runtime.task_archive import validate_controller_archive_reference

UNIT_FIELDS={'domain','policy','runtime_output','evaluator_policy','evaluator_assignment_directory',
    'gate_policy','gate_journal_directory','gate_review_path','retirement_journal_directory',
    'archive_policy_path','archive_sources','archive_gate_policy','archive_gate_journal_directory',
    'archive_review_path','resource_context','admission_wait_seconds'}


def produce_formal_phase(assignment_path):
    if os.geteuid()!=21010 or not {21001,21003}.issubset(set(os.getgroups())|{os.getegid()}):
        raise PermissionError('phase_producer_actual_admin_custody')
    job=read_owned(assignment_path,uid=21001,gid=21010,limit=8388608)
    fields={'kind','campaign_id','config','compiled','plan','source_grant_paths','unit_templates',
        'campaign_started_at','campaign_deadline','whole_round_manifest_path','output_directory','digest'}
    generated=(fields-{'compiled','plan'})|{'compiled_path','plan_revision_path'}
    if set(job) not in (fields,fields|{'parent_phase_path'},generated,generated|{'parent_phase_path'}) or job['kind']!='FrozenFormalDevelopmentPhaseProduction':
        raise ValueError('phase_producer_original_assignment')
    whole=read_round_manifest(job['whole_round_manifest_path'])
    from skillloop.runtime.whole_source import whole_source_index
    if digest_jcs(whole_source_index(Path(__file__).resolve().parents[2]))!=whole['source_digest']:
        raise ValueError('phase_producer_actual_frozen_source')
    campaign=next((c for c in whole['campaigns'] if c['campaign_digest']==job['campaign_id']),None)
    config=job['config']
    if 'compiled_path' in job:
        from skillloop.discovery.compiled_authority import current_compilation
        compiled=current_compilation(job['compiled_path'],campaign_id=job['campaign_id'],config=config)
        revision=read_owned(job['plan_revision_path'],uid=21010,gid=21001,limit=2097152)
        if (revision.get('kind')!='AdminCampaignPlanRevision' or revision.get('campaign_id')!=job['campaign_id']
                or revision.get('deployment_epoch')!=whole['deployment_epoch'] or revision.get('suite')!=compiled['suite']):
            raise ValueError('phase_producer_actual_produced_plan_revision')
        plan=revision['plan']
    else:
        if config.get('whole_flow_required') is True:
            raise ValueError('phase_producer_formal_gate_compilation_required')
        compiled,plan=job['compiled'],job['plan']
    validate_suite(compiled['suite'],list(compiled['cases'].values()),compiled['objectives'])
    validate_plan(plan,compiled['suite'])
    deadline=datetime.fromisoformat(job['campaign_deadline'].replace('Z','+00:00'))
    if (campaign is None or config.get('whole_flow_required') is not True
            or config.get('deployment_epoch')!=whole['deployment_epoch']
            or config.get('mac_runtime_image')!=whole['image']
            or config.get('worker_deadline_seconds')!=campaign['victim_seconds']
            or plan['body']['phase']!='dev' or plan['body']['campaign_id']!=job['campaign_id']
            or plan['body']['config_digest']!=digest_jcs(config)
            or compiled['profile_id']!=campaign['profile']
            or compiled['suite']['body']['visibility']!='public_dev'
            or type(job['campaign_started_at']) not in (int,float)
            or deadline.tzinfo is None or deadline.timestamp()!=job['campaign_started_at']+28800
            or not job['campaign_started_at']<=datetime.now(timezone.utc).timestamp()<deadline.timestamp()):
        raise ValueError('phase_producer_original_whole_identity_and_clock')
    required=[i for i in plan['body']['items'] if i['requirement']=='required']
    from skillloop.discovery.phase_chain import development_parent
    parent=development_parent({'phase':'dev','plan':plan,'suite':compiled['suite'],
        'whole_round_manifest_digest':whole['digest'],'campaign_started_at':job['campaign_started_at'],
        'campaign_deadline':job['campaign_deadline'],'parent_phase_path':job.get('parent_phase_path')})
    previous={i['item_id'] for i in parent['plan']['body']['items'] if i['requirement']=='required'} if parent else set()
    fresh=[i for i in required if i['item_id'] not in previous]
    if (not required or len(required)>campaign['reserved_victim_attempts']
            or not fresh
            or type(job['unit_templates']) is not dict
            or set(job['unit_templates'])!={i['item_id'] for i in fresh}
            or any(i['phase']!='dev' or i['attempts_reserved']!=1
                or i['timeout_ms']!=campaign['victim_seconds']*1000 for i in required)):
        raise ValueError('phase_producer_full_required_rows')
    sources={}
    if type(job['source_grant_paths']) is not list or not 1<=len(job['source_grant_paths'])<=4:
        raise ValueError('phase_producer_bounded_sources')
    for path in job['source_grant_paths']:
        grant=read_owned(path,uid=21010,gid=21003,limit=2097152)
        if (grant.get('kind')!='AdminCampaignSourceAdmission' or grant.get('campaign_id')!=job['campaign_id']
                or grant.get('deployment_epoch')!=whole['deployment_epoch'] or grant.get('config')!=config
                or grant.get('subject_digest') in sources):
            raise ValueError('phase_producer_current_source_grant')
        validate_source_admission(grant['admission'],config,grant['subject_digest'])
        sources[grant['subject_digest']]=grant['admission']
    if set(sources)!={i['subject_digest'] for i in required}:
        raise ValueError('phase_producer_exact_subject_coverage')
    # Only frozen public business worlds are used. New finding/history cases
    # must retain an exact fixture identity; no private factory is consulted.
    fixtures={}
    for suffix in ('a','b'):
        manifest=FAMILY_SPEC/'fixtures'/campaign['profile']/('clean-'+suffix)/'manifest.json'
        inputs,_=load_clean_fixture(campaign['profile'],suffix)
        fixtures[digest_bytes(manifest.read_bytes())]=inputs
    cases={case['digest']:(name,case) for name,case in compiled['cases'].items()}
    entries=[];cost=120;locators=set();aux=campaign['stages']['development']
    for item in fresh:
        name,case=cases[item['case_digest']]
        inputs=fixtures.get(case['body']['fixture_digest'])
        if inputs is None:raise ValueError('phase_producer_frozen_public_fixture_required')
        if digest_jcs({'profile_id':campaign['profile'],'inputs':{
                k:digest_bytes(v) for k,v in inputs.items() if k!='notes'}})!=case['body']['business_projection_digest']:
            raise ValueError('phase_producer_business_projection')
        admission=sources[item['subject_digest']]
        current={**compiled,'subject_digest':item['subject_digest'],
            'skill_digest':digest_bytes(base64.b64decode(admission['package_files']['SKILL.md'],validate=True))}
        entry={'entry_id':'formal-dev-'+digest_jcs({'campaign':job['campaign_id'],'plan':plan['digest'],
            'item':item['item_id']})[7:],'campaign_id':job['campaign_id'],'profile':campaign['profile'],
            'role':item['subject_role'],'case_id':name,'repetition':item['repetition_index'],
            'source_index_digest':whole['source_digest'],'config':config,'compiled':current,'plan':plan,
            'source_admission':admission}
        entry['digest']=digest_jcs(entry)
        verify_formal_entry(entry,image=whole['image'],source_digest=whole['source_digest'],model_port=config['model_service_port'])
        unit=job['unit_templates'][item['item_id']]
        if type(unit) is not dict or set(unit)!=UNIT_FIELDS:
            raise ValueError('phase_producer_complete_task_template')
        unit={**unit,'entry':entry,'inputs':{k:base64.b64encode(v).decode('ascii') for k,v in inputs.items()}}
        for field in ('evaluator_policy','gate_policy','archive_gate_policy'):
            policy=unit[field]
            if (type(policy) is not dict or 'entry_digest' in policy or 'digest' in policy
                    or policy.get('image')!=whole['image'] or policy.get('deployment_epoch')!=whole['deployment_epoch']
                    or policy.get('campaign_deadline')!=job['campaign_deadline']
                    or type(policy.get('timeout_seconds')) is not int or not 1<=policy['timeout_seconds']<=1200):
                raise ValueError('phase_producer_current_independent_policy_template')
            policy={**policy,'entry_digest':entry['digest']};policy['digest']=digest_jcs(policy);unit[field]=policy
        for field in ('runtime_output','evaluator_assignment_directory','gate_journal_directory',
                'gate_review_path','retirement_journal_directory','archive_gate_journal_directory','archive_review_path'):
            path=unit[field]
            if (type(path) is not str or not Path(path).is_absolute() or str(Path(path))!=path
                    or '..' in Path(path).parts or path in locators):
                raise ValueError('phase_producer_unique_current_task_locators')
            locators.add(path)
        archive=read_owned(unit['archive_policy_path'],uid=21010,gid=21001,limit=262144)
        validate_controller_archive_reference(archive)
        if (archive.get('kind')!='FrozenDurableTaskArchive' or archive['digest']!=config.get('durable_task_archive_policy_digest')
                or archive['image']!=whole['image'] or archive['deployment_epoch']!=whole['deployment_epoch']
                or archive['campaign_deadline']!=job['campaign_deadline']):
            raise ValueError('phase_producer_current_archive_policy')
        if (set(unit['evaluator_policy'].get('mounts',{}))!={'assignment','runtime','snapshot','evaluation','tokenizer'}
                or set(unit['gate_policy'].get('mounts',{}))!={'assignment','runtime','snapshot','evaluation','tokenizer','reviews'}
                or any(unit['evaluator_policy']['mounts'][k]!=unit['gate_policy']['mounts'][k]
                    for k in unit['evaluator_policy']['mounts'])
                or unit['resource_context'].get('proxy_server_uid')!=21003
                or unit['resource_context'].get('tokenizer_mount')!=unit['evaluator_policy']['mounts']['tokenizer']
                or set(unit['archive_sources'])!={'runtime','authority','evaluation','gate'}
                or unit['archive_sources']['runtime']!=unit['runtime_output']
                or unit['archive_sources']['gate']!=unit['gate_review_path']
                or set(unit['archive_gate_policy'].get('mounts',{}))!={'archive','original_reviews','reviews'}
                or unit['archive_gate_policy']['mounts']['archive']!={'volume':archive['archive_volume'],'subpath':'.'}
                or unit['archive_gate_policy']['mounts']['original_reviews']!=unit['gate_policy']['mounts']['reviews']
                or unit['archive_gate_policy'].get('maximum_bytes')!=archive['maximum_bytes']
                or unit['archive_gate_policy'].get('maximum_files')!=archive['maximum_files']):
            raise ValueError('phase_producer_same_actual_custody_and_archive_scope')
        seconds=(unit['admission_wait_seconds']+unit['evaluator_policy']['timeout_seconds']
            +unit['gate_policy']['timeout_seconds']+archive['timeout_seconds']+unit['archive_gate_policy']['timeout_seconds']+120)
        disk=(unit['evaluator_policy']['maximum_database_bytes']+config['maximum_runtime_evidence_bytes']
            +2097152+archive['maximum_bytes'])
        if type(unit['admission_wait_seconds']) is not int or not 1<=unit['admission_wait_seconds']<=60:
            raise ValueError('phase_producer_admission_bound')
        if (type(config.get('proxy_deadline_seconds')) is not int
                or not 1<=config['proxy_deadline_seconds']<=300
                or config['worker_deadline_seconds']+unit['admission_wait_seconds']+10>=config['proxy_deadline_seconds']):
            raise ValueError('phase_producer_original_lease_full_cost')
        if seconds>aux['seconds'] or disk>aux['disk_bytes']:
            raise ValueError('phase_producer_complete_auxiliary_reservation')
        cost+=campaign['victim_seconds']+seconds;entries.append(unit)
    if (len(entries)>aux['count'] or cost>campaign['phase_reservations']['dev']
            or cost>(deadline-datetime.now(timezone.utc)).total_seconds()):
        raise ValueError('phase_producer_complete_phase_cost')
    phase={'kind':'FrozenFormalPhase','phase':'dev','whole_round_manifest_digest':whole['digest'],
        'plan':plan,'suite':compiled['suite'],'entries':entries,'campaign_started_at':job['campaign_started_at'],
        'campaign_deadline':job['campaign_deadline'],'reserved_phase_seconds':campaign['phase_reservations']['dev'],
        'terminal_seconds':120}
    if parent is not None:phase['parent_phase_path']=job['parent_phase_path']
    phase['digest']=digest_jcs(phase)
    if len(canonical_json_line(phase))>8388608:raise ValueError('phase_producer_complete_document_capacity')
    output=_directory(job['output_directory'],21010,21001,0o750);target=output/'phase.json'
    if os.path.lexists(target):
        if read_owned(target,uid=21010,gid=21001,limit=8388608)!=phase:
            raise ValueError('phase_producer_original_output_conflict')
    else:_publish(target,phase,21001)
    result={'kind':'AdminFormalPhaseProduced','assignment_digest':job['digest'],'phase_digest':phase['digest'],
        'required_items':len(required),'new_items':len(entries),'carried_items':len(previous),
        'complete_cost_seconds':cost,'proxy_admission_verified':False,
        'runtime_executed':False,'qualification_issued':False}
    result['digest']=digest_jcs(result);return result
