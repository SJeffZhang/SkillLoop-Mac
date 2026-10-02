"""Actual bounded authority/WAL/evidence exercise; zero model, no CaseResult."""
from contextlib import closing
import errno,json,os,sqlite3,time,platform
from pathlib import Path
from skillloop.proxy.store import ProxyStore
from skillloop.families.task_world import fixture,stamp
from skillloop.protocol import digest_jcs,digest_bytes
p=json.loads(Path('/plan.json').read_text());assert p['digest']==digest_jcs({k:v for k,v in p.items() if k!='digest'})
root=Path('/state/private');root.mkdir(mode=0o700);os.chmod(root,0o700)
assert time.time()-p['started_unix']<p['wall_budget_seconds']
free=lambda:os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
assert os.statvfs(root).f_blocks*os.statvfs(root).f_frsize==p['volume_bytes']
reserve=root/'recovery.reserve';fd=os.open(reserve,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
os.posix_fallocate(fd,0,p['recovery_reserve_bytes']);os.fsync(fd);os.close(fd)
store=ProxyStore(root/'authority.sqlite',deployment_epoch=p['deployment_epoch'])
d,policy,b,req,a,raw=fixture(run_id='quota-lifecycle-run-v3',task_instance_id='quota-lifecycle-task-v3')
store.stage_approval(d,a);store.activate_approval(a['digest'],0,operation_id='activate-v1',request_digest=digest_jcs('activate-v1'))
store.stage_task(domain=d,policy=policy,binding=b,run_request=req,profile_id='orders_total',resources=raw,approval_digest=a['digest'],run_deadline=stamp(600),campaign_id=p['config'])
lease=store.start_run(req['digest'],b['digest'],operation_id='start-v1',request_digest=digest_jcs('start-v1'))
owned=root/'run-evidence';owned.mkdir(mode=0o700)
complete=owned/'committed-observation.bin';data=b'new synthetic quota evidence\n'*2048
with complete.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
os.chmod(complete,0o600)
writer=sqlite3.connect(store.path,isolation_level=None);writer.execute('PRAGMA synchronous=FULL');writer.execute('PRAGMA wal_autocheckpoint=0')
# Engineering pressure row is isolated from business authority tables, but uses
# the actual authority database and its real WAL on the evidence filesystem.
writer.execute('CREATE TABLE engineering_quota_pressure (id INTEGER PRIMARY KEY, revision INTEGER, payload BLOB)')
writer.execute('INSERT INTO engineering_quota_pressure VALUES(1,0,?)',(bytes([0])*262144,))
reader=sqlite3.connect(store.path,isolation_level=None);reader.execute('BEGIN');reader.execute('SELECT revision FROM engineering_quota_pressure').fetchone()
commits=0;sqlite_full=None
for n in range(1,512):
 try:
  writer.execute('BEGIN IMMEDIATE');writer.execute('UPDATE engineering_quota_pressure SET revision=?,payload=? WHERE id=1',(n,bytes([n%251])*262144));writer.execute('COMMIT');commits=n
 except sqlite3.DatabaseError as error:
  sqlite_full={'type':type(error).__name__,'message':str(error),'sqlite_errorcode':getattr(error,'sqlite_errorcode',None),'sqlite_errorname':getattr(error,'sqlite_errorname',None)}
  if writer.in_transaction:writer.execute('ROLLBACK')
  break
assert sqlite_full and sqlite_full['sqlite_errorcode']==sqlite3.SQLITE_FULL
assert writer.execute('SELECT revision FROM engineering_quota_pressure').fetchone()[0]==commits
wal=Path(str(store.path)+'-wal');assert wal.exists()
peak_wal=wal.stat().st_size;free_after_wal=free()
# Evidence attempts fail against the very same physical filesystem limit.
partial=owned/'incomplete-pressure.bin';evidence_full=None;written=0
fd=os.open(partial,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
try:
 for _ in range(64):
  chunk=b'E'*524288
  while chunk:
   try:n=os.write(fd,chunk);written+=n;chunk=chunk[n:]
   except OSError as error:
    assert error.errno==errno.ENOSPC;evidence_full={'errno':error.errno,'message':str(error)};break
  if evidence_full:break
finally:os.close(fd)
assert evidence_full and free()==0
# Observe actual authority cancellation separately: a small transaction can
# reuse already allocated WAL frames, even when statvfs reports zero free.
cancel_error=None
try:store.cancel_run(b['body']['run_id'],1,operation_id='full-cancel-v1',request_digest=digest_jcs('full-cancel-v1'))
except sqlite3.DatabaseError as error:cancel_error={'type':type(error).__name__,'message':str(error),'sqlite_errorcode':getattr(error,'sqlite_errorcode',None)}
with closing(sqlite3.connect(store.path)) as db:
 full_state=db.execute('SELECT state,fence FROM runs WHERE run_id=?',(b['body']['run_id'],)).fetchone()
 full_operations=db.execute("SELECT count(*) FROM operations WHERE operation_id='full-cancel-v1'").fetchone()[0]
 assert (full_state,full_operations)==((('active',1),0) if cancel_error else (('cancelled',2),1))
partial_hash=digest_bytes(partial.read_bytes());devices={x.stat().st_dev for x in (root,store.path,wal,reserve,complete,partial)};assert len(devices)==1
# Recovery only frees this new activity's quarantined incomplete write/reserve.
partial.unlink();reserve.unlink();reader.rollback();reader.close()
checkpoint=writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone();assert checkpoint[0]==0;writer.close()
assert complete.read_bytes()==data
cancel_key='recovered-cancel-v1' if cancel_error else 'full-cancel-v1'
store.cancel_run(b['body']['run_id'],1,operation_id=cancel_key,request_digest=digest_jcs(cancel_key))
with closing(sqlite3.connect(store.path)) as db:
 assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
 assert db.execute('SELECT revision FROM engineering_quota_pressure').fetchone()[0]==commits
 assert db.execute('SELECT state,fence FROM runs').fetchone()==('cancelled',2)
 with closing(sqlite3.connect(root/'authority.backup.sqlite')) as backup:db.backup(backup)
os.chmod(root/'authority.backup.sqlite',0o600)
with closing(sqlite3.connect(root/'authority.backup.sqlite')) as db:assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
receipt={'kind':'ActualAuthorityEvidenceQuotaReceipt','config':p['config'],'plan_digest':p['digest'],'epoch':p['deployment_epoch'],'platform':platform.machine(),'volume_bytes':p['volume_bytes'],'run_id':b['body']['run_id'],'lease_digest':lease['digest'],'filesystem_device':devices.pop(),'same_filesystem':True,'committed_wal_updates':commits,'peak_wal_bytes':peak_wal,'free_after_wal_failure':free_after_wal,'sqlite_full':sqlite_full,'evidence_enospc':evidence_full,'incomplete_evidence_bytes':written,'incomplete_evidence_digest':partial_hash,'incomplete_evidence_quarantined_then_removed':True,'authority_cancel_at_full_error':cancel_error,'authority_at_full_state':list(full_state),'authority_at_full_operation_count':full_operations,'blanket_write_refusal_claimed':False,'recovered_cancel_state':'cancelled','recovered_fence':2,'checkpoint_result':list(checkpoint),'integrity':'ok','original_complete_evidence_digest':digest_bytes(data),'recovery_reserve_released':True,'model_calls':0,'formal_m10_complete':False,'production_ready':False,'elapsed_seconds':time.time()-p['started_unix']}
receipt['digest']=digest_jcs(receipt)
with (root/'receipt.json').open('x') as f:json.dump(receipt,f,indent=2)
os.chmod(root/'receipt.json',0o600)
index={'kind':'StoppedControllerEvidenceInventory','files':[{'path':str(x.relative_to(root)),'bytes':x.stat().st_size,'digest':digest_bytes(x.read_bytes())} for x in sorted(root.rglob('*')) if x.is_file()]};index['digest']=digest_jcs(index)
with (root/'EXPORT-INDEX.json').open('x') as f:json.dump(index,f,indent=2)
print(json.dumps({'receipt_digest':receipt['digest'],'index_digest':index['digest'],'sqlite_full':sqlite_full,'evidence_enospc':True,'fence':2}),flush=True)
