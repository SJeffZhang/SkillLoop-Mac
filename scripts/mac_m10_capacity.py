"""Measured disk headroom and isolated queue enforcement diagnostics."""
import argparse,json,os,time
from pathlib import Path
from skillloop.protocol import digest_jcs
from skillloop.repair.budget import SpendingLedger

GiB=1024**3

def disk_admission(host_free,vm_free):
    # Retain original 50 GiB Mac working reserve plus 2 GiB additional activity.
    # VM reserve covers two max-sized 2 GiB campaign copies plus 2 GiB scratch.
    reasons=[]
    if host_free<52*GiB:reasons.append('host_working_and_activity_reserve')
    if vm_free<6*GiB:reasons.append('vm_activity_backup_and_scratch_reserve')
    return {'admission':'rejected' if reasons else 'ready','host_free_bytes':host_free,'vm_free_bytes':vm_free,'host_required_bytes':52*GiB,'vm_required_bytes':6*GiB,'reasons':reasons,'scope':'current headroom admission; not a physical disk exhaustion or sustained load test'}


def rejects(operation,reason):
    try:operation()
    except ValueError as error:
        if str(error)!=reason:raise
        return True
    raise ValueError('capacity_boundary_did_not_reject:'+reason)


def queue_boundaries(root):
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if list(root.glob('*.json')):raise ValueError('capacity_diagnostic_exists')
    started=time.time();count=SpendingLedger(root/'attempt-limit.json',victim_seconds=1,campaign_started_at=started)
    for index in range(128):count.consume('diagnostic.slot.'+str(index),0)
    overflow=rejects(lambda:count.consume('diagnostic.overflow',0),'execution_budget_exhausted')
    wall=SpendingLedger(root/'wall-limit.json',victim_seconds=265,campaign_started_at=started)
    for index in range(108):wall.consume('diagnostic.wall.'+str(index),0)
    wall_overflow=rejects(lambda:wall.consume('diagnostic.wall.overflow',0),'execution_budget_exhausted')
    expired=SpendingLedger(root/'expired-clock.json',victim_seconds=265,campaign_started_at=started-28801)
    expired_rejected=rejects(lambda:expired.consume('diagnostic.expired',0),'execution_budget_exhausted')
    resumed=SpendingLedger(root/'wall-limit.json',victim_seconds=265,campaign_started_at=started)
    duplicate=rejects(lambda:resumed.consume('diagnostic.wall.0',0),'execution_already_spent')
    clock=rejects(lambda:SpendingLedger(root/'wall-limit.json',victim_seconds=265,campaign_started_at=started+1),'campaign_clock_changed')
    return {'scope':'isolated diagnostic ledgers; no victim execution or model calls','attempt_limit_consumed':128,'attempt_overflow_rejected':overflow,'wall_budget_consumed':108,'wall_overflow_rejected':wall_overflow,'expired_clock_rejected':expired_rejected,'duplicate_after_restart_rejected':duplicate,'clock_reset_rejected':clock,'new_model_calls':0}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();os.umask(0o077);r=queue_boundaries(a.root);r['digest']=digest_jcs(r);(a.root/'receipt.json').write_text(json.dumps(r,indent=2));print(r)
