"""Read only an exact same-round append-only development phase predecessor."""
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from scripts.spec_v22_core import validate_plan


def development_parent(phase):
    path=phase.get('parent_phase_path')
    if path is None:return None
    parent=read_owned(path,uid=21010,gid=21001,limit=8388608)
    if (parent.get('kind')!='FrozenFormalPhase' or parent.get('phase')!='dev'
            or parent.get('digest')!=digest_jcs({k:v for k,v in parent.items() if k!='digest'})
            or phase.get('phase')!='dev' or any(parent.get(k)!=phase.get(k) for k in
                ('whole_round_manifest_digest','campaign_started_at','campaign_deadline'))):
        raise ValueError('formal_phase_same_round_original_parent')
    old,new=parent['plan'],phase['plan']
    validate_plan(old,parent['suite']);validate_plan(new,phase['suite'])
    if (new['body']['parent_plan_digest']!=old['digest']
            or new['body']['revision']!=old['body']['revision']+1
            or any(old['body'][k]!=new['body'][k] for k in ('campaign_id','config_digest','phase'))
            or new['body']['items'][:len(old['body']['items'])]!=old['body']['items']
            or len(new['body']['items'])<=len(old['body']['items'])):
        raise ValueError('formal_phase_append_only_original_plan')
    cases={c['case_digest']:c for c in phase['suite']['body']['cases']}
    if any(cases.get(c['case_digest'])!=c for c in parent['suite']['body']['cases']):
        raise ValueError('formal_phase_parent_case_semantics_changed')
    return parent
