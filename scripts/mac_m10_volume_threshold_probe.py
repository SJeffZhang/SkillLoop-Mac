import json,os,sqlite3,platform,time,sys,multiprocessing
from pathlib import Path
from skillloop.runtime.reserved_queue import ReservedProxyStore
from skillloop.proxy.store import ProxyError
from skillloop.families.task_world import fixture,stamp
from skillloop.protocol import digest_jcs,digest_bytes
plan=json.loads(Path('/plan.json').read_text());mode=sys.argv[1];root=Path('/state/private');root.mkdir(mode=0o700);os.chmod(root,0o700)
assert plan['digest']==digest_jcs({k:v for k,v in plan.items() if k!='digest'})
assert time.time()-plan['started_unix']<plan['wall_budget_seconds']
floor=plan['free_floor_bytes'];walbytes=plan['wal_headroom_reservation_bytes'];perrun=plan['per_run_reservation_bytes'];cap=plan['maximum_physical_allocation_bytes']
fs=lambda:os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
before=fs();assert before>=floor+walbytes
if mode=='positive':assert before>=floor+walbytes+perrun
if mode=='positive':assert before>=floor+cap+floor
wal=root/'database-wal-headroom.reserve';fd=os.open(wal,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
try:
 os.posix_fallocate(fd,0,walbytes);os.pwrite(fd,b'SkillLoop-new-volume-WAL-headroom-v1',walbytes-4096);os.fsync(fd)
finally:os.close(fd)
assert wal.stat().st_size==walbytes and wal.stat().st_blocks*512>=walbytes
args={'deployment_epoch':plan['deployment_epoch']+'-'+mode,'queue_capacity':16,'reservation_bytes':perrun,'free_floor_bytes':floor}
dbpath=root/'authority.sqlite';store=ReservedProxyStore(dbpath,**args);requests=[]
for n in range(16 if mode=='positive' else 1):
 d,p,b,r,a,raw=fixture(run_id=f'volume-v3-{mode}-run-{n}',task_instance_id=f'volume-v3-{mode}-task-{n}')
 if n==0:
  approval=a['digest'];store.stage_approval(d,a);store.activate_approval(approval,0,operation_id='activate',request_digest=digest_jcs('activate'))
 store.stage_task(domain=d,policy=p,binding=b,run_request=r,profile_id='orders_total',resources=raw,approval_digest=approval,run_deadline=stamp(600),campaign_id='volume-'+mode)
 requests.append((r,b))
evid=root/'owned-evidence';evid.mkdir(mode=0o700)
allocated_after_wal=fs();mappings=[];denied=None
if mode=='positive':
 for n,(r,b) in enumerate(requests):
  lease=store.start_run(r['digest'],b['digest'],operation_id=f'start-{n}',request_digest=digest_jcs(f'start-{n}'))
  ep=evid/f'{n}.json';data=json.dumps({'run_id':b['body']['run_id'],'lease_digest':lease['digest'],'entry_kind':'new zero-model filesystem audit, not CaseResult'},sort_keys=True).encode()
  fd=os.open(ep,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
  try:os.write(fd,data);os.fsync(fd)
  finally:os.close(fd)
  with sqlite3.connect(dbpath) as db:
   row=db.execute('SELECT run_id,filename,bytes,state FROM storage_reservations WHERE run_id=?',(b['body']['run_id'],)).fetchone()
  rp=store.reservation_directory/row[1];st=rp.stat()
  assert row[2:]==(perrun,'held') and st.st_blocks*512>=perrun and st.st_size==perrun
  assert len({x.stat().st_dev for x in (root,wal,dbpath,store.reservation_directory,rp,evid,ep)})==1
  assert st.st_uid==ep.stat().st_uid==wal.stat().st_uid==os.getuid()==0
  mappings.append({'run_id':row[0],'reservation_filename':row[1],'bytes':row[2],'allocated_bytes':st.st_blocks*512,'reservation_device':st.st_dev,'evidence_filename':ep.name,'evidence_digest':digest_bytes(data),'evidence_bytes':len(data),'evidence_device':ep.stat().st_dev,'owner_uid':st.st_uid,'reservation_mode':st.st_mode&0o777,'evidence_mode':ep.stat().st_mode&0o777})
 assert fs()>=floor and walbytes+sum(x['allocated_bytes'] for x in mappings)<=cap
 # Real lower UID cannot access trusted DB, evidence or physical reservations.
 paths=[str(dbpath),str(wal),str(evid/'0.json'),str(store.reservation_directory/mappings[0]['reservation_filename'])]
 def unauthorized(q):
  os.setuid(21002);found=[]
  for name in paths:
   try:
    with open(name,'rb') as f:f.read(1)
    found.append('unexpected_access')
   except PermissionError:found.append('denied')
  q.put(found)
 q=multiprocessing.Queue();child=multiprocessing.Process(target=unauthorized,args=(q,));child.start();denied=q.get(timeout=10);child.join(10);assert child.exitcode==0 and denied==['denied']*4
 # Reopen the actual deployment on the same volume: all held ownership persists.
 store=ReservedProxyStore(dbpath,**args)
 for n,(r,b) in enumerate(requests):
  store.cancel_run(b['body']['run_id'],1,operation_id=f'cancel-{n}',request_digest=digest_jcs(f'cancel-{n}'))
 assert not list(store.reservation_directory.glob('*.reserve')) and all((evid/x['evidence_filename']).is_file() for x in mappings)
else:
 assert floor<=fs()<floor+perrun
 r,b=requests[0]
 try:store.start_run(r['digest'],b['digest'],operation_id='start-0',request_digest=digest_jcs('start-0'))
 except ProxyError as error:assert error.code=='storage_floor';denied=error.code
 else:raise AssertionError('actual exact-floor admission should refuse')
 with sqlite3.connect(dbpath) as db:
  assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==0
  assert db.execute("SELECT count(*) FROM operations WHERE operation_id='start-0'").fetchone()[0]==0
 assert not list(store.reservation_directory.glob('*.reserve'))
# A live reader pins the actual SQLite WAL so all authority paths can be mapped.
conn=sqlite3.connect(dbpath);conn.execute('PRAGMA journal_mode=WAL');conn.execute('BEGIN');conn.execute('SELECT count(*) FROM runs').fetchone()
with sqlite3.connect(dbpath) as writer:writer.execute("UPDATE trust_state SET trust_revision=trust_revision WHERE singleton=1")
walactual=Path(str(dbpath)+'-wal');assert walactual.exists() and walactual.stat().st_dev==wal.stat().st_dev
with sqlite3.connect('/evidence/authority.backup.sqlite') as backup:conn.backup(backup)
conn.rollback();conn.close()
with sqlite3.connect('/evidence/authority.backup.sqlite') as db:
 assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
 runs=db.execute('SELECT count(*) FROM runs').fetchone()[0]
 assert runs==(16 if mode=='positive' else 0)
# Export actual tiny owned evidence before releasing the separate headroom file.
for item in mappings:
 data=(evid/item['evidence_filename']).read_bytes();assert digest_bytes(data)==item['evidence_digest']
 with (Path('/evidence')/item['evidence_filename']).open('xb') as f:f.write(data)
body={'kind':'ActualEvidenceVolumeThresholdReceipt','config':plan['config'],'mode':mode,'plan_digest':plan['digest'],'platform':platform.machine(),'device':root.stat().st_dev,'available_before_bytes':before,'available_after_wal_bytes':allocated_after_wal,'actual_floor_bytes':floor,'actual_wal_headroom_bytes':walbytes,'wal_allocated_bytes':wal.stat().st_blocks*512,'run_reserved_bytes_at_peak':sum(x['allocated_bytes'] for x in mappings),'physical_cap_bytes':cap,'evidence_mapping':mappings,'other_uid_access':denied,'same_filesystem_authority_wal_reservation_evidence':True,'actual_sqlite_wal_is_separate_from_headroom_file':True,'all_run_reservations_released_evidence_retained':mode=='positive','negative_no_run_or_operation_commit':mode=='negative','sqlite_integrity':'ok','model_calls':0,'formal_r38_complete':False,'formal_m10_complete':False,'production_ready':False,'elapsed_seconds_original_clock':time.time()-plan['started_unix']}
body['digest']=digest_jcs(body)
with Path('/evidence/receipt.json').open('x') as f:json.dump(body,f,indent=2)
assert body['elapsed_seconds_original_clock']<plan['wall_budget_seconds']
wal.unlink();assert not wal.exists()
print(json.dumps({'mode':mode,'runs':runs,'peak_reserved':body['run_reserved_bytes_at_peak']+walbytes,'floor':floor,'denied':denied,'receipt_digest':body['digest']}))
