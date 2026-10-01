"""Bind Mac protection admission to the closed M6 evidence and original clock."""
import math
from skillloop.protocol import digest_jcs
from skillloop.repair.spending import remaining_capacity


def checked(record):
    if record.get('digest') != digest_jcs({k:v for k,v in record.items() if k!='digest'}):
        raise ValueError('admission_record_digest')
    return record


def admit_profile(gate, manifest, clock, ledger, *, profile, expected_executions, at_unix_ms):
    """No calls, no new clock, and no acceptance for incomplete paired evidence."""
    checked(gate);checked(manifest);checked(clock)
    if gate['campaign_digest']!=manifest['digest'] or clock['manifest_digest']!=manifest['digest'] or gate['config_digest']!=digest_jcs(manifest['config']):
        raise ValueError('m6_admission_binding')
    row=gate['profiles'][profile];info=manifest['profiles'][profile];freeze=checked(row['freeze'])
    if row['verdict']!='pass' or row['errors'] or row['missing'] or freeze['status']!='frozen' or freeze['reasons'] or freeze['subject']!=info['inheritance']['candidate_subject_digest'] or row['actual_attempts']!=info['required_runs']:
        raise ValueError('m6_not_qualified')
    keys=[(x['item_key'],x['attempt']) for x in ledger['executions']]
    expected=[(x['item_key'],x['attempt']) for x in expected_executions]
    seconds=manifest['config']['worker_deadline_seconds']
    if seconds!=265 or len(keys)!=len(set(keys)) or len(expected)!=len(set(expected)) or set(keys)!=set(expected) or any(a!=0 for _,a in keys) or ledger['victim_attempts']!=len(keys) or ledger['retries']!=0 or ledger['charged_wall_seconds']!=len(keys)*seconds or ledger['campaign_started_at']!=clock['started_at'] or not math.isfinite(ledger['elapsed_seconds']) or ledger['elapsed_seconds']<0:
        raise ValueError('m6_spending_binding')
    capacity=remaining_capacity(ledger,started_at_unix_ms=int(clock['started_at']*1000),at_unix_ms=at_unix_ms,planned_attempts=len(keys)+24+2,auxiliary_seconds=720)
    body={'kind':'MacM7Admission','profile':profile,'admission':capacity['admission'],'m6_gate_digest':gate['digest'],'freeze_digest':freeze['digest'],'manifest_digest':manifest['digest'],'prior_spending_digest':digest_jcs(ledger),'original_clock_digest':clock['digest'],'protected_required_runs':24,'remaining_capacity':capacity,'at_unix_ms':at_unix_ms,'production_ready':False}
    return {**body,'digest':digest_jcs(body)}
