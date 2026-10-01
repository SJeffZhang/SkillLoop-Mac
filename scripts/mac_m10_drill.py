"""Isolated VM volume recovery/cancellation/archive drill; no model calls."""
import argparse,json,os,sqlite3,tarfile
from pathlib import Path
from contextlib import closing
from skillloop.protection.recovery import restore_authority
from skillloop.proxy.store import ProxyStore,ProxyError
from skillloop.protocol import digest_bytes,digest_jcs


def drill(source,root,new_epoch):
    os.umask(0o077);root.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(root,0o700)
    source_digest=digest_bytes(source.read_bytes());cancel=root/'cancellation.sqlite'
    if cancel.exists():raise FileExistsError('drill_already_exists')
    with closing(sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)) as original,closing(sqlite3.connect(cancel)) as copy:
        original.backup(copy);copy.execute('PRAGMA journal_mode=DELETE')
        epoch=copy.execute('SELECT deployment_epoch FROM trust_state').fetchone()[0];run=copy.execute('SELECT run_id,fence FROM runs LIMIT 1').fetchone()
    if run is None:raise ValueError('drill_requires_real_run')
    store=ProxyStore(cancel,deployment_epoch=epoch);operation='m10-cancel-drill';request=digest_jcs([operation,run])
    first=store.cancel_run(run[0],run[1],operation_id=operation,request_digest=request)
    repeated=store.cancel_run(run[0],run[1],operation_id=operation,request_digest=request)
    if first!=repeated:raise ValueError('cancellation_not_idempotent')
    try:store.cancel_run(run[0],run[1],operation_id='m10-stale-fence',request_digest=digest_jcs('stale'))
    except ProxyError as error:
        if 'stale_fence' not in str(error):raise
    else:raise ValueError('stale_fence_accepted')
    restored=root/'restored.sqlite';receipt=restore_authority(source,restored,new_epoch=new_epoch);ProxyStore(restored,deployment_epoch=new_epoch)
    try:ProxyStore(restored,deployment_epoch=epoch)
    except ProxyError as error:
        if 'deployment_epoch_mismatch' not in str(error):raise
    else:raise ValueError('old_epoch_accepted')
    with closing(sqlite3.connect(restored)) as db:
        if db.execute("SELECT count(*) FROM approvals WHERE state!='revoked'").fetchone()[0] or db.execute("SELECT count(*) FROM runs WHERE state!='cancelled'").fetchone()[0]:raise ValueError('restored_capabilities_not_revoked')
        if db.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise ValueError('drill_integrity')
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.execute('PRAGMA journal_mode=DELETE')
    with closing(sqlite3.connect(cancel)) as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.execute('PRAGMA journal_mode=DELETE')
    files={p.name:digest_bytes(p.read_bytes()) for p in (cancel,restored)}
    archive=root/'recovery-archive.tar'
    with tarfile.open(archive,'w') as tar:
        for p in (cancel,restored):tar.add(p,arcname=p.name,recursive=False)
    with tarfile.open(archive,'r') as tar:
        if {p.name:digest_bytes(tar.extractfile(p).read()) for p in tar.getmembers()}!=files:raise ValueError('archive_content_mismatch')
    if source_digest!=digest_bytes(source.read_bytes()):raise ValueError('source_changed')
    body={'kind':'MacM10IsolatedRecoveryDrill','source_digest':source_digest,'source_unchanged':True,'restore':receipt,'cancel_idempotent':True,'stale_cancel_fence_rejected':True,'old_epoch_rejected':True,'archive_digest':digest_bytes(archive.read_bytes()),'archive_file_hashes':files,'archive_content_verified':True,'new_model_calls':0,'formal_m10_complete':False};body['digest']=digest_jcs(body);(root/'receipt.json').write_text(json.dumps(body,indent=2));return body

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--new-epoch',required=True);a=p.parse_args();r=drill(a.source,a.root,a.new_epoch);print({k:r[k] for k in ('source_unchanged','cancel_idempotent','stale_cancel_fence_rejected','old_epoch_rejected','archive_content_verified')})
