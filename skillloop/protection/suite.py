"""Compile an approved fresh private factory proposal, only in the private role."""
from skillloop.discovery.suite import _objectives
from skillloop.discovery.mutation import make_dev_mutation, compile_mutation
from skillloop.protocol import digest_jcs, digest_bytes, make_envelope
from skillloop.families.registry import FAMILY_SPEC
from scripts.spec_v22_core import validate_plan

def compile_private(bundle, tokenizer, development):
    objectives=_objectives(); cases=dict(development["cases"]); mutations=dict(development["mutations"])
    private_ids=[]
    fixture_digest=digest_jcs({'inputs':{k:digest_bytes(v) for k,v in bundle['inputs'].items()},
        'expected':digest_bytes(bundle['expected_bytes'])})
    for row in bundle['cases']:
        mutation=None
        if row['mutation']:
            mutation=make_dev_mutation(profile_id=bundle['profile_id'],source_bytes=bundle['inputs']['notes'],
                payload_bytes=row['mutation']['payload'])
            compile_mutation(mutation,source_bytes=bundle['inputs']['notes'],profile_id=bundle['profile_id'],count_tokens=tokenizer.count_text)
            mutations[row['case_id']]=mutation
        pair=cases[row['clean_pair_id']]['digest'] if row['clean_pair_id'] else None
        private_ids.append(row['case_id'])
        cases[row['case_id']]=make_envelope('CaseTemplate',{'case_id':row['case_id'],'case_kind':row['kind'],
            'split':'protected','fixture_digest':fixture_digest,'business_projection_digest':bundle['business_projection_digest'],
            'mutation_digest':mutation['digest'] if mutation else None,'clean_pair_digest':pair,
            'objective_ids':row['objective_ids'],'repetitions':3})
    entries=[{'case_digest':c['digest'],**{k:c['body'][k] for k in ('case_kind','split','repetitions',
        'objective_ids','clean_pair_digest','business_projection_digest','fixture_digest','mutation_digest')}} for c in cases.values()]
    suite=make_envelope('SuiteManifest',{'suite_id':bundle['epoch_id'],'profile_id':bundle['profile_id'],
        'epoch_id':bundle['epoch_id'],'visibility':'private_evaluation','objective_registry_digest':digest_jcs(objectives),
        'cases':entries,'base_case_digests':development['suite']['body']['base_case_digests']+[cases[cid]['digest'] for cid in private_ids],
        'history_case_digests':development['suite']['body']['history_case_digests']})
    return {'profile_id':bundle['profile_id'],'objectives':objectives,'cases':cases,'mutations':mutations,'suite':suite}

def protected_plan(compiled, subjects, campaign, config, parent=None, *, runtime_profile_path=None):
    if type(subjects) is not dict or set(subjects) not in ({'submitted'}, {'submitted','finalist'}, {'submitted','active'}, {'submitted','finalist','active'}):
        raise ValueError('protected_subject_set')
    # Contract identity is (subject, case, repetition), not a role label.
    # A finalist or active identical to submitted reuses its existing rows;
    # inventing duplicate runs would both violate validate_plan and spend twice.
    distinct={};seen=set()
    for role in ('submitted','finalist','active'):
        if role not in subjects:continue
        subject=subjects[role]
        if subject['subject_digest'] not in seen:
            distinct['active_baseline' if role=='active' else role]=subject;seen.add(subject['subject_digest'])
    timeout=265000
    if config.get('whole_flow_required'):
        seconds=config.get('worker_deadline_seconds')
        if type(seconds) is not int or not 1<=seconds<=300:
            raise ValueError('protected_frozen_worker_timeout_required')
        timeout=seconds*1000
    items=[{'item_id':role+'.'+cid+'.'+str(rep),'subject_digest':subject['subject_digest'],
        'case_digest':case['digest'],'repetition_index':rep,'phase':case['body']['split'],'subject_role':role,
        'requirement':'required','reason_code':None,'attempts_reserved':1,'timeout_ms':timeout}
        for role,subject in distinct.items() for cid,case in compiled['cases'].items() for rep in range(case['body']['repetitions'])
        if parent is None or case['body']['split']=='protected']
    if parent: items=list(parent['body']['items'])+items
    budget = config.get('protected_budget')
    if budget is not None:
        if (type(budget) is not dict or set(budget) != {'reserved_auxiliary_ms','terminal_reserve_ms'}
                or any(type(v) is not int or v <= 0 for v in budget.values())):
            raise ValueError('protected_complete_budget')
    elif config.get('whole_flow_required'):
        raise ValueError('protected_complete_budget_required')
    else:
        budget = {'reserved_auxiliary_ms':120000,'terminal_reserve_ms':600000}
    p=make_envelope('ExecutionPlan',{'campaign_id':campaign,'revision':parent['body']['revision']+1 if parent else 1,'parent_plan_digest':parent['digest'] if parent else None,
        'suite_digest':compiled['suite']['digest'],'config_digest':digest_jcs(config),'phase':'protected',
        'items':items,'reserved_rollouts':len(items),'reserved_execution_ms':sum(i['timeout_ms']*i['attempts_reserved'] for i in items),
        'reserved_auxiliary_ms':budget['reserved_auxiliary_ms'],'terminal_reserve_ms':budget['terminal_reserve_ms'],'max_campaign_rollouts':128,
        'max_campaign_execution_ms':28800000,'runtime_profile_digest':digest_bytes((runtime_profile_path or FAMILY_SPEC.parent/'operations/runtime-profile.json').read_bytes())})
    validate_plan(p,compiled['suite']);return p
