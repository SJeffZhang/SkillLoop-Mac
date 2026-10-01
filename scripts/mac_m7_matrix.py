"""Private protection queue: durable delivery fence and spent-slot recovery."""
import argparse,fcntl,time
from pathlib import Path
from scripts.mac_m6_gate import load,sealed,result_path
from scripts.mac_m6_matrix import execute,save,model_identity
from scripts.dgx_m6_repair import source_index
from skillloop.protocol import digest_jcs
from skillloop.protection.authority import ProtectionAuthority
from skillloop.repair.budget import SpendingLedger
from skillloop.repair.spending import remaining_capacity


def delivery_action(state,spent):
    if state is None:
        if spent:raise ValueError('unbound_protected_spending')
        return 'dispatch'
    if not spent or state[0] not in {'delivered','unknown','complete'}:raise ValueError('protected_delivery_recover_only')
    return 'recover'


def validate_retired_slot(state,spent):
    if not spent or state!=('unknown',None):raise ValueError('retired_slot_must_be_spent_unknown')


def run(root,source):
    lock=(root/'run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    manifest=sealed(load(root/'manifest.json'));config=manifest['config']
    if source_index(source)!=manifest['source_index']:raise ValueError('protected_source_changed')
    model_identity(config)
    authority=ProtectionAuthority(root.parent/'mac-m7-private-authority')
    ledger=SpendingLedger(root/'spending.json',victim_seconds=265,campaign_started_at=manifest['clock']['started_at'])
    state=load(root/'status.json')
    if state['manifest_digest']!=manifest['digest']:raise ValueError('protected_resume_manifest')
    entries=[sealed(load(root/p)) for p in manifest['entries']]
    for entry in entries:
        key=digest_jcs([config['deployment_epoch'],manifest['campaign_id'],manifest['epoch_id'],entry['compiled']['subject_digest'],entry['compiled']['cases'][entry['case_id']]['digest'],entry['repetition']])
        spent=any(e['item_key']==entry['entry_id'] and e['attempt']==0 for e in ledger.read()['executions'])
        if entry['entry_id'] in manifest.get('retired_entries',{}):
            validate_retired_slot(authority.state(key),spent)
            state['entries'][entry['entry_id']]='retained_incomplete_predecessor'
            save(root/'status.json',state)
            continue
        action=delivery_action(authority.state(key),spent)
        if action=='dispatch':
            capacity=remaining_capacity(ledger.read(),started_at_unix_ms=int(manifest['clock']['started_at']*1000),at_unix_ms=int(time.time()*1000),planned_attempts=len(manifest['prior_ledger']['executions'])+26,auxiliary_seconds=720)
            if capacity['admission']!='ready':raise ValueError('protected_remaining_budget_rejected')
            reserved=authority.reserve(config['deployment_epoch'],manifest['campaign_id'],manifest['epoch_id'],entry['compiled']['subject_digest'],entry['compiled']['cases'][entry['case_id']]['digest'],entry['repetition'])
            if reserved!=key:raise ValueError('protected_session_identity')
            authority.transition(key,'reserved','delivered')
        outcome=execute(root,Path('/unused'),entry,ledger)
        path=result_path(root,entry)
        session=authority.state(key)
        if path.exists() and session[0]=='delivered':authority.transition(key,'delivered','complete',load(path)['result']['digest'])
        elif not path.exists() and session[0]=='delivered':authority.transition(key,'delivered','unknown')
        state['entries'][entry['entry_id']]=outcome
        bodies=[load(result_path(root,e))['result']['body'] for e in entries if result_path(root,e).exists()]
        state.update(phase='running',actual_attempts=sum(x['item_key'].startswith('protected.') for x in ledger.read()['executions']),complete=sum(b['coverage_complete'] for b in bodies),incomplete=sum(not b['coverage_complete'] for b in bodies)+len(manifest.get('retired_entries',{})),confirmed_failures=sum(b['security_violation'] or b['utility_status']=='fail' for b in bodies))
        save(root/'status.json',state);print(entry['entry_id'],outcome,flush=True)
        if outcome not in {'exported','retained_completed'}:
            state.update(phase='infrastructure_attention');save(root/'status.json',state);return
    save(root/'execution-closed.json',{'ledger':ledger.read(),'finished_at_unix_ms':int(time.time()*1000),'manifest_digest':manifest['digest']})
    state.update(phase='awaiting_independent_gate');save(root/'status.json',state)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--source',type=Path,required=True);a=p.parse_args();run(a.root.resolve(),a.source.resolve())
