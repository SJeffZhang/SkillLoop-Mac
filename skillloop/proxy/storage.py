"""Formal business SQLite capacity and campaign admission, on its actual FS.

Preallocation uses the business database's real reusable free pages. There is
no placeholder resource file and no mock lease. WAL is checkpointed before a
writer; the database/page/frame bound and observed sizes share a fixed budget.
"""
from contextlib import contextmanager, closing
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import time
import sys
from contextvars import ContextVar

from skillloop.protocol import digest_jcs
from skillloop.proxy.store import ProxyStore, ProxyError, _stamp, _now
from skillloop.proxy.wire import make_control


FORMAL_STORAGE_POLICY={'queue_capacity':16,'free_floor_bytes':2147483648,
                       'database_wal_reserve_bytes':536870912,'campaign_disk_bytes':2147483648}


class FormalStorageStore(ProxyStore):
    def __init__(self,path,*,deployment_epoch,policy,campaigns,authority_projection_directory,snapshot_directory):
        if os.geteuid()!=21003:raise PermissionError('formal_storage_proxy_owner')
        required={'queue_capacity','free_floor_bytes','database_wal_reserve_bytes','campaign_disk_bytes'}
        if (type(policy) is not dict or set(policy)!=required
                or policy!=FORMAL_STORAGE_POLICY):
            raise ValueError('formal_storage_frozen_policy')
        database_path=Path(path)
        filesystem=database_path.parent.stat().st_dev
        if (any(Path(directory).stat().st_dev!=filesystem
                for directory in (authority_projection_directory,snapshot_directory))
                or database_path.exists() and database_path.stat().st_dev!=filesystem):
            raise ProxyError('storage_authority_or_snapshot_other_filesystem')
        from skillloop.proxy.task_admission import validate_campaign_catalog
        validate_campaign_catalog(campaigns)
        from skillloop.proxy.qualification_authority import LiveAuthorityProjection
        self.authority_projection=LiveAuthorityProjection(authority_projection_directory,deployment_epoch)
        self.storage_policy=policy;self.capacity_campaigns=campaigns;self.capacity_ready=False
        self._emergency=ContextVar('formal_proxy_emergency_'+deployment_epoch,default=False)
        self._wal_anchor=None
        super().__init__(path,deployment_epoch=deployment_epoch)
        with self._writer_lock(),closing(sqlite3.connect(self.path,isolation_level=None,timeout=2)) as db:
            db.execute('PRAGMA synchronous=FULL')
            if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:raise ProxyError('storage_checkpoint_busy')
            if db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]!='delete':raise ProxyError('storage_checkpoint_busy')
            if db.execute('PRAGMA auto_vacuum').fetchone()[0]!=0:raise ProxyError('storage_auto_vacuum_not_admitted')
            page=db.execute('PRAGMA page_size').fetchone()[0]
            # cache_spill=OFF below keeps one WAL frame per dirty page. Reserve
            # frame headers, WAL header, and a further 64-page safety margin.
            self.maximum_pages=(policy['database_wal_reserve_bytes']-32)//(2*page+24)-64
            if db.execute('PRAGMA page_count').fetchone()[0]>self.maximum_pages:
                raise ProxyError('storage_existing_database_over_capacity')
            db.execute('PRAGMA max_page_count='+str(self.maximum_pages))
            db.execute('CREATE TABLE IF NOT EXISTS formal_storage_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),policy TEXT NOT NULL,page_limit INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS campaign_storage_reservations(campaign TEXT PRIMARY KEY,plan TEXT NOT NULL,generation INTEGER NOT NULL,disk_bytes INTEGER NOT NULL,state TEXT NOT NULL,committed_at TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS formal_storage_emergency(singleton INTEGER PRIMARY KEY CHECK(singleton=1),normal_used_page_limit INTEGER NOT NULL,emergency_pages INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS formal_campaign_cancellations(campaign TEXT PRIMARY KEY,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,committed_at TEXT NOT NULL)')
            identity=digest_jcs({'epoch':deployment_epoch,'policy':policy,'campaigns':campaigns,'cancellation_version':1})
            prior=db.execute('SELECT policy,page_limit FROM formal_storage_identity WHERE singleton=1').fetchone()
            if prior and prior!=(identity,self.maximum_pages):raise ProxyError('storage_identity_changed')
            self._floor(policy['database_wal_reserve_bytes'] if prior is None else 0)
            if prior is None:
                # Allocate pages in the actual SQLite file, then return them to
                # SQLite's freelist. Its normal business writes reuse those pages.
                db.execute('CREATE TABLE formal_storage_preallocation(bytes BLOB NOT NULL)')
                db.execute('PRAGMA cache_size=-327680')
                db.execute('PRAGMA cache_spill=OFF')
                db.execute('BEGIN IMMEDIATE')
                try:
                    target_pages=self.maximum_pages*95//100
                    while db.execute('PRAGMA page_count').fetchone()[0]<target_pages:
                        db.execute('INSERT INTO formal_storage_preallocation VALUES(zeroblob(1048576))')
                    db.execute('DELETE FROM formal_storage_preallocation')
                    allocated=db.execute('PRAGMA page_count').fetchone()[0]
                    db.execute('INSERT INTO formal_storage_emergency VALUES(1,?,64)',(allocated-64,))
                    db.execute('INSERT INTO formal_storage_identity VALUES(1,?,?)',(identity,self.maximum_pages))
                    db.execute('COMMIT')
                except BaseException:
                    db.execute('ROLLBACK');raise
            info=self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21003
                    or info.st_size>policy['database_wal_reserve_bytes']
                    or info.st_blocks*512<info.st_size):
                raise ProxyError('storage_real_database_allocation_required')
            emergency=db.execute('SELECT normal_used_page_limit,emergency_pages FROM formal_storage_emergency WHERE singleton=1').fetchone()
            if (emergency is None or emergency[1]!=64 or not 1<emergency[0]<self.maximum_pages
                    or (prior is None and db.execute('PRAGMA freelist_count').fetchone()[0]<64)):
                raise ProxyError('storage_emergency_actual_free_pages_required')
            self.normal_used_pages=emergency[0]
            db.execute('PRAGMA journal_mode=WAL')
            # Keep an actual connection alive. Otherwise SQLite removes WAL on
            # the final close, silently throwing away its physical reservation.
            self._wal_anchor=super()._connect()
            self._wal_anchor.execute('PRAGMA max_page_count='+str(self.maximum_pages))
            self._wal_anchor.execute('PRAGMA cache_size=-327680')
            self._wal_anchor.execute('PRAGMA cache_spill=OFF')
            self._wal_anchor.execute('PRAGMA wal_autocheckpoint=0')
            self._wal_anchor.execute('CREATE TABLE IF NOT EXISTS formal_storage_wal_preallocation(bytes BLOB NOT NULL)')
            if self._wal_anchor.execute('PRAGMA wal_checkpoint(RESTART)').fetchone()[0]:
                raise ProxyError('storage_checkpoint_busy')
            self._wal_anchor.execute('BEGIN IMMEDIATE')
            try:
                # Write the existing free pages through the real WAL, then
                # return them to SQLite. These are not filesystem placeholders.
                # Retain enough free pages for bounded emergency event writes.
                while True:
                    pages=self._wal_anchor.execute('PRAGMA page_count').fetchone()[0]
                    free=self._wal_anchor.execute('PRAGMA freelist_count').fetchone()[0]
                    available=self.maximum_pages-pages+free-32
                    if available<=4:break
                    size=min(1048576,(available-4)*page)
                    self._wal_anchor.execute('INSERT INTO formal_storage_wal_preallocation VALUES(zeroblob(?))',(size,))
                self._wal_anchor.execute('DELETE FROM formal_storage_wal_preallocation')
                self._wal_anchor.execute('COMMIT')
            except BaseException:
                self._wal_anchor.execute('ROLLBACK');raise
            if self._wal_anchor.execute('PRAGMA wal_checkpoint(RESTART)').fetchone()[0]:
                raise ProxyError('storage_checkpoint_busy')
            wal=Path(str(self.path)+'-wal');wal_info=wal.lstat()
            actual_database=self.path.lstat()
            if (not stat.S_ISREG(wal_info.st_mode) or wal_info.st_uid!=21003
                    or wal_info.st_blocks*512<wal_info.st_size
                    or not stat.S_ISREG(actual_database.st_mode) or actual_database.st_uid!=21003
                    or actual_database.st_blocks*512<actual_database.st_size
                    or actual_database.st_size+wal_info.st_size>policy['database_wal_reserve_bytes']):
                raise ProxyError('storage_real_wal_allocation_required')
        self.capacity_ready=True
        with self.authority_projection.writing():
            self.authority_projection.publish_from(self)

    @contextmanager
    def _writer_lock(self):
        path=Path(self.path).with_name(Path(self.path).name+'.capacity.lock')
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=21003 or info.st_mode&0o077:
                raise PermissionError('formal_storage_lock_owner')
            deadline=time.monotonic()+2
            while True:
                self._check_rpc_clock()
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise ProxyError('storage_writer_busy')
                    time.sleep(0.02)
            self._check_rpc_clock()
            yield
        finally:os.close(fd)

    def _floor(self,additional=0):
        fs=os.statvfs(self.path.parent)
        if fs.f_bavail*fs.f_frsize<self.storage_policy['free_floor_bytes']+additional:
            raise ProxyError('storage_floor')

    def _connect(self):
        db=super()._connect()
        if getattr(self,'capacity_ready',False):
            db.execute('PRAGMA max_page_count='+str(self.maximum_pages))
            db.execute('PRAGMA cache_size=-327680')
            db.execute('PRAGMA cache_spill=OFF')
            db.execute('PRAGMA wal_autocheckpoint=1')
        return db

    @contextmanager
    def _transaction(self):
        if not getattr(self,'capacity_ready',False):
            with super()._transaction() as db:yield db
            return
        with self._writer_lock():
            emergency=self._emergency.get()
            if not emergency:self._floor()
            with closing(self._connect()) as checkpoint:
                if checkpoint.execute('PRAGMA wal_checkpoint(RESTART)').fetchone()[0]:
                    raise ProxyError('storage_checkpoint_busy')
            with self.authority_projection.writing():
                try:
                    with super()._transaction() as db:
                        yield db
                        if db.execute('PRAGMA page_count').fetchone()[0]>self.maximum_pages:
                            raise ProxyError('storage_database_capacity_exceeded')
                        used=db.execute('PRAGMA page_count').fetchone()[0]-db.execute('PRAGMA freelist_count').fetchone()[0]
                        if not emergency and used>self.normal_used_pages:
                            raise ProxyError('storage_emergency_pages_reserved')
                    # AFTER COMMIT errors remain unknown to the caller.
                    sizes=sum(p.stat().st_size for p in (self.path,Path(str(self.path)+'-wal')) if p.exists())
                    if sizes>self.storage_policy['database_wal_reserve_bytes']:
                        raise sqlite3.OperationalError('storage_database_wal_capacity_exceeded_after_commit')
                finally:
                    primary=sys.exc_info()[1]
                    try:self.authority_projection.publish_from(self)
                    except BaseException as error:
                        if primary is None:raise
                        primary.add_note('live_authority_sync_incomplete:'+type(error).__name__)

    def cancel_run(self,run_id,expected_fence,*,operation_id,request_digest):
        token=self._emergency.set(True)
        try:
            with self._transaction() as db:
                previous=self._operation_replay(db,operation_id,request_digest)
                if previous is not None:return previous
                run=self._one(db,'SELECT * FROM runs WHERE run_id=?',(run_id,))
                cancelled=db.execute('SELECT committed_at FROM formal_campaign_cancellations WHERE campaign=?',
                    (run['campaign_id'],)).fetchone()
                if cancelled and run['state']=='cancelled' and run['fence']==expected_fence+1:
                    # Original worker retirement after Admin cancellation only
                    # observes that exact already committed business fence.
                    # It cannot revive a run, advance a second fence, or admit
                    # stale tooling. The immutable Admin event stays intact.
                    event=digest_jcs({'run_id':run_id,'fence':run['fence'],'state':'cancelled'})
                    row=db.execute("SELECT committed_at FROM accepted_events WHERE run_id=? AND event_type='run_cancelled' AND event_digest=?",(run_id,event)).fetchall()
                    if len(row)!=1:raise ProxyError('denied')
                    result={'run_id':run_id,'fence':run['fence'],'committed_at':row[0][0],
                            'campaign_id':run['campaign_id']}
                    self._record_operation(db,operation_id,'controller',run_id,request_digest,'cancel_run',result)
                    return result
                return self._cancel_run_in_transaction(db,run_id,expected_fence,
                    operation_id=operation_id,request_digest=request_digest)
        finally:self._emergency.reset(token)

    def cancel_campaign_run(self,campaign,run_id,expected_fence,*,operation_id,request_digest):
        """Delegate Admin campaign cancellation through authenticated cancel_run.

        Fence all original runs and deny future starts in the same business
        commit. Ordinary worker retirement continues to cancel only its run.
        No lost response is replayed with a new identity.
        """
        if campaign not in self.capacity_campaigns:raise ProxyError('denied')
        token=self._emergency.set(True)
        try:
            with self._transaction() as db:
                prior=self._operation_replay(db,operation_id,request_digest)
                if prior is not None:return prior
                run=self._one(db,'SELECT * FROM runs WHERE run_id=?',(run_id,))
                if run['campaign_id']!=campaign:raise ProxyError('denied')
                result=self._cancel_run_in_transaction(db,run_id,expected_fence,
                    operation_id=operation_id,request_digest=request_digest)
                now=result['committed_at']
                db.execute('INSERT OR IGNORE INTO formal_campaign_cancellations VALUES(?,?,?,?)',
                    (campaign,operation_id,request_digest,now))
                # Any concurrently admitted run committed before this writer
                # fence also becomes unusable; later starts see the tombstone.
                for other in db.execute("SELECT run_id,fence FROM runs WHERE campaign_id=? AND run_id!=? AND state IN ('active','finalizing')",(campaign,run_id)).fetchall():
                    fence=other['fence']+1
                    db.execute("UPDATE runs SET state='cancelled',fence=? WHERE run_id=?",(fence,other['run_id']))
                    event=digest_jcs({'run_id':other['run_id'],'fence':fence,'state':'cancelled'})
                    db.execute("INSERT INTO accepted_events(run_id,event_type,event_digest,committed_at) VALUES(?,'run_cancelled',?,?)",(other['run_id'],event,now))
                return result
        finally:self._emergency.reset(token)

    @staticmethod
    def _require_uncancelled_campaign(db,campaign):
        if db.execute('SELECT 1 FROM formal_campaign_cancellations WHERE campaign=?',(campaign,)).fetchone():
            raise ProxyError('cancelled')

    def _active_run(self,db,run_id,fence):
        result=super()._active_run(db,run_id,fence)
        self._require_uncancelled_campaign(db,result[0]['campaign_id'])
        return result

    def revoke_approval(self,*args,**kwargs):
        token=self._emergency.set(True)
        try:return super().revoke_approval(*args,**kwargs)
        finally:self._emergency.reset(token)

    def recover_tool(self,*args,**kwargs):
        # Recovery takes the real writer fence but does not add new effects.
        token=self._emergency.set(True)
        try:return super().recover_tool(*args,**kwargs)
        finally:self._emergency.reset(token)

    def close(self):
        """Called only after accepted writers and snapshot exports have drained."""
        if self._wal_anchor is not None:
            self._wal_anchor.close();self._wal_anchor=None

    def reserve_campaign(self,campaign,plan,*,operation_id,request_digest):
        pins=self.capacity_campaigns.get(campaign)
        if pins is None:raise ProxyError('denied')
        with self._transaction() as db:
            old=self._operation_replay(db,operation_id,request_digest)
            if old is not None:return old
            self._require_uncancelled_campaign(db,campaign)
            head=db.execute('SELECT plan FROM controller_plan_heads WHERE campaign=?',(campaign,)).fetchone()
            if head is None or head[0]!=plan:raise ProxyError('version_conflict')
            previous=db.execute('SELECT plan,generation,disk_bytes,state FROM campaign_storage_reservations WHERE campaign=?',(campaign,)).fetchone()
            if previous and tuple(previous)!=(plan,pins['generation'],pins['disk_bytes'],'reserved'):
                raise ProxyError('version_conflict')
            if not previous:
                if db.execute("SELECT count(*) FROM campaign_storage_reservations WHERE state='reserved'").fetchone()[0]>=16:
                    raise ProxyError('queue_full')
                held=db.execute("SELECT coalesce(sum(disk_bytes),0) FROM campaign_storage_reservations WHERE state='reserved'").fetchone()[0]
                self._floor(held+pins['disk_bytes'])
                db.execute("INSERT INTO campaign_storage_reservations VALUES(?,?,?,?,'reserved',?)",(campaign,plan,pins['generation'],pins['disk_bytes'],_stamp(_now())))
            result=make_control('CampaignInspection',{'campaign_public_ref':campaign,'state':'reserved',
                'generation':pins['generation'],'qualification':'none','report_digest':None})
            self._record_operation(db,operation_id,'controller',None,request_digest,'reserve_campaign',result)
            return result

    def _admit_start_capacity(self, db, task):
        self._require_uncancelled_campaign(db,task['campaign_id'])
        pins=self.capacity_campaigns.get(task['campaign_id'])
        if pins is None:raise ProxyError('denied')
        reservation=db.execute('SELECT plan,generation,disk_bytes,state FROM campaign_storage_reservations WHERE campaign=?',(task['campaign_id'],)).fetchone()
        head=db.execute('SELECT plan FROM controller_plan_heads WHERE campaign=?',(task['campaign_id'],)).fetchone()
        if head is None or reservation is None or tuple(reservation)!=(head[0],pins['generation'],pins['disk_bytes'],'reserved'):
            raise ProxyError('storage_reservation_required')
        self._floor()
