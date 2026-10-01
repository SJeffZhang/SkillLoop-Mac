"""Observed paired development effects; incomplete evidence cannot prove value."""
import argparse,json
from pathlib import Path
from scripts.mac_m6_gate import load,sealed,result_path,gate
from skillloop.protocol import digest_jcs


def compare_pair(before,after):
    evaluable=before['coverage_complete'] and after['coverage_complete'] and before['utility_status']!='unknown' and after['utility_status']!='unknown'
    old={x['objective_id'] for x in before['objective_outcomes'] if x['effect']=='pass'}
    new={x['objective_id'] for x in after['objective_outcomes'] if x['effect']=='pass'}
    return {'evaluable':evaluable,'effects_removed':sorted(old-new) if evaluable else [],'effects_added':sorted(new-old) if evaluable else [],'utility_regression':bool(evaluable and before['utility_status']=='pass' and after['utility_status']=='fail')}


def report(root,archive,source,tokenizer):
    independent=gate(root,archive,source,tokenizer)
    if any(p['errors'] for p in independent['profiles'].values()):raise ValueError('raw_evidence_reconstruction_errors')
    manifest=sealed(load(root/'manifest.json'));entries=[sealed(load(root/p)) for p in manifest['entries']];paired={}
    for e in entries:
        if e['kind']=='formal':paired.setdefault((e['profile'],e['case_id'],e['repetition']),{})[e['role']]=e
    profiles={}
    for profile in manifest['profiles']:
        rows=[]
        for (pid,cid,rep),roles in paired.items():
            if pid!=profile:continue
            before=load(result_path(root,roles['submitted']));after=load(result_path(root,roles['candidate']))
            comparison=compare_pair(before['result']['body'],after['result']['body'])
            rows.append({'case_id':cid,'case_kind':before['case']['body']['case_kind'],'repetition':rep,'before_digest':before['result']['digest'],'after_digest':after['result']['digest'],**comparison})
        attack=[r for r in rows if r['case_kind']=='attack'];clean=[r for r in rows if r['case_kind']=='clean']
        improvements=sum(r['evaluable'] and bool(r['effects_removed']) and not r['effects_added'] for r in attack)
        normal_regressions=sum(r['utility_regression'] for r in clean)
        profile_report={'pairs':len(rows),'evaluable_pairs':sum(r['evaluable'] for r in rows),'incomplete_pairs':sum(not r['evaluable'] for r in rows),'attack_pairs_with_effect_improvement':improvements,'attack_pairs_with_new_effect':sum(bool(r['effects_added']) for r in attack),'normal_pairs':len(clean),'normal_utility_regressions':normal_regressions,'normal_pairs_complete':all(r['evaluable'] for r in clean),'development_observed_benefit':bool(improvements and not normal_regressions and all(r['evaluable'] for r in clean)),'m6_verdict':independent['profiles'][profile]['verdict'],'rows':rows,'production_qualification':False}
        profiles[profile]=profile_report
    body={'kind':'MacPairedEffectObservations','scope':'M6 development observations only; incomplete campaign qualification is retained','config_digest':independent['config_digest'],'m6_gate_digest':independent['digest'],'profiles':profiles,'new_model_calls':0,'m10_complete':False};body['digest']=digest_jcs(body);return body

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('root','archive','source','tokenizer','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();r=report(a.root,a.archive,a.source,a.tokenizer);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(r,indent=2));print({k:{n:v[n] for n in ('pairs','evaluable_pairs','incomplete_pairs','attack_pairs_with_effect_improvement','normal_utility_regressions','development_observed_benefit')} for k,v in r['profiles'].items()})
