"""Live approval projection, serialized with actual business transactions.

Readers hold the shared guard through qualification consumption. The Proxy
holds its exclusive guard through business commit and projection publication.
A pending marker means publication was interrupted and consumption is denied.
This exports approval and current plan-head metadata only; no task inputs,
private case or business database grant.
"""
from contextlib import contextmanager, closing
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import stat
import time

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs


def _directory(path):
    root=Path(path);info=root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21003 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('live_authority_projection_directory')
    return root


def _open(root,name,flags):
    fd=os.open(root/name,flags|os.O_NOFOLLOW|os.O_NONBLOCK)
    info=os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21003 or info.st_gid!=21001
            or stat.S_IMODE(info.st_mode)!=0o640 or info.st_size>2097152):
        os.close(fd);raise PermissionError('live_authority_projection_file')
    return fd


def _sync(root):
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def _lock(fd,mode):
    deadline=time.monotonic()+2
    while True:
        try:fcntl.flock(fd,mode|fcntl.LOCK_NB);return
        except BlockingIOError:
            if time.monotonic()>=deadline:raise TimeoutError('live_authority_projection_busy')
            time.sleep(0.02)


class LiveAuthorityProjection:
    def __init__(self,directory,epoch):
        if os.geteuid()!=21003:raise PermissionError('live_authority_proxy_writer')
        self.root=_directory(directory);self.epoch=epoch
        if not os.path.lexists(self.root/'guard'):
            self._write('guard',b'')
        fd=_open(self.root,'guard',os.O_RDONLY);os.close(fd)
        if os.path.lexists(self.root/'pending.json'):
            raise RuntimeError('live_authority_interrupted_sync_requires_reconciliation')

    def _write(self,name,raw):
        if len(raw)>2097152:raise ValueError('live_authority_projection_capacity')
        fd=os.open(self.root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),-1,21001);os.fchmod(stream.fileno(),0o640)
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        _sync(self.root)

    @contextmanager
    def writing(self):
        fd=_open(self.root,'guard',os.O_RDONLY)
        try:
            _lock(fd,fcntl.LOCK_EX)
            if os.path.lexists(self.root/'pending.json'):
                raise RuntimeError('live_authority_interrupted_sync_requires_reconciliation')
            self._write('pending.json',canonical_json_line({'kind':'LiveAuthorityWritePending',
                'deployment_epoch':self.epoch,'started_at':datetime.now(timezone.utc).isoformat()}))
            yield
        finally:os.close(fd)

    def publish_from(self,store,*,clear_pending=True):
        # Called while the exclusive guard is held, after commit OR rollback.
        with closing(store._connect()) as db:
            db.execute('BEGIN')
            identity=db.execute('SELECT deployment_epoch,trust_revision FROM trust_state WHERE singleton=1').fetchone()
            if identity is None or identity[0]!=self.epoch:raise ValueError('live_authority_actual_epoch')
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            complete={'issued_domain_approvals','factory_approvals'}<=tables
            approvals=[]
            if complete:
                cursor=db.execute('''SELECT a.approval_digest,a.state,a.expires_at,i.config_digest,
                    i.factory_approval_ref,f.approval_ref,f.expires_at FROM approvals a
                    JOIN issued_domain_approvals i ON i.approval_ref=a.approval_digest
                    LEFT JOIN factory_approvals f ON f.profile=i.factory_profile_digest
                    ORDER BY a.approval_digest LIMIT 1025''')
                for row in cursor:
                    approvals.append(dict(zip(('approval_digest','state','expires_at','config_digest',
                        'issued_factory_ref','current_factory_ref','factory_expires_at'),row)))
                if len(approvals)>1024:raise ValueError('live_authority_approval_capacity')
            heads=[]
            if 'controller_plan_heads' in tables:
                rows=db.execute('SELECT campaign,plan,revision_digest FROM controller_plan_heads ORDER BY campaign LIMIT 4').fetchall()
                if len(rows)>3:raise ValueError('live_authority_campaign_head_capacity')
                heads=[{'campaign_id':row[0],'plan_digest':row[1],'revision_digest':row[2]} for row in rows]
            sources=[]
            if 'controller_source_admissions' in tables:
                rows=db.execute('SELECT campaign,subject,admission_digest,source_pins,authorization FROM controller_source_admissions ORDER BY campaign,subject LIMIT 13').fetchall()
                if len(rows)>12:raise ValueError('live_authority_source_capacity')
                for campaign,subject,admission,raw,authorization in rows:
                    pins=decode_json(raw);grant=decode_json(authorization)
                    sources.append({'campaign_id':campaign,'subject_digest':subject,
                        'source_snapshot_digest':pins['source_snapshot_digest'],
                        'skill_manifest_digest':pins['skill_manifest_digest'],'admission_digest':admission,
                        'authorization_digest':grant['digest'],'git_provenance':pins['git_provenance']})
            value={'kind':'LiveQualificationAuthority','deployment_epoch':self.epoch,
                'trust_revision':identity[1],'complete':complete,'approvals':approvals,
                'plan_heads':heads,'source_admissions':sources,
                'observed_at':datetime.now(timezone.utc).isoformat()}
            value['digest']=digest_jcs(value)
        self._write('current.pending',canonical_json_line(value))
        os.replace(self.root/'current.pending',self.root/'current.json');_sync(self.root)
        if clear_pending:
            os.unlink(self.root/'pending.json');_sync(self.root)


@contextmanager
def current_authority(directory,*,epoch,config_digest,trust_revision,approval_digests):
    # The protected Evaluator also needs the effective approval guard while
    # committing its fresh Factory epoch. This is read-only metadata, not a
    # grant to the business database or another role's private cases.
    if os.geteuid() not in {21001,21004,21005}:raise PermissionError('live_authority_consumer_role')
    root=_directory(directory);fd=_open(root,'guard',os.O_RDONLY)
    try:
        _lock(fd,fcntl.LOCK_SH)
        if os.path.lexists(root/'pending.json'):
            raise ValueError('qualification_authority_sync_incomplete')
        value_fd=_open(root,'current.json',os.O_RDONLY)
        with os.fdopen(value_fd,'rb') as stream:value=decode_json(stream.read(2097153))
        if (value.get('kind')!='LiveQualificationAuthority' or value.get('complete') is not True
                or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'})
                or value.get('deployment_epoch')!=epoch or value.get('trust_revision')!=trust_revision):
            raise ValueError('qualification_authority_changed')
        rows={a['approval_digest']:a for a in value['approvals']}
        if not approval_digests:raise ValueError('qualification_actual_approval_missing')
        now=datetime.now(timezone.utc)
        for digest in approval_digests:
            a=rows.get(digest)
            if (a is None or a['state']!='active' or a['config_digest']!=config_digest
                    or not a['current_factory_ref'] or a['issued_factory_ref']!=a['current_factory_ref']):
                raise ValueError('qualification_approval_revoked')
            for expiry in (a['expires_at'],a['factory_expires_at']):
                if expiry is not None:
                    date=datetime.fromisoformat(expiry.replace('Z','+00:00'))
                    if date.tzinfo is None or date<=now:raise ValueError('consumption_expired')
        yield value
    finally:os.close(fd)


def reconcile_interrupted(directory,database,*,epoch,expected_pending_digest,deadline):
    """Explicit restart repair of metadata only, from the actual existing DB.

    No approval, task, model slot or old qualification is recreated. An admin
    restart authorization pins the observed pending marker and original UTC.
    """
    import sqlite3
    from skillloop.protocol import digest_bytes
    if os.geteuid()!=21003:raise PermissionError('live_authority_proxy_reconciliation')
    end=datetime.fromisoformat(deadline.replace('Z','+00:00'))
    if end.tzinfo is None or not 60<(end-datetime.now(timezone.utc)).total_seconds()<=28800:
        raise TimeoutError('live_authority_original_recovery_budget')
    root=_directory(directory);database=Path(database)
    info=database.lstat();parent=database.parent.lstat()
    if (not database.is_absolute() or database.is_symlink() or database.parent.is_symlink()
            or not stat.S_ISREG(info.st_mode) or info.st_uid!=21003 or stat.S_IMODE(info.st_mode)!=0o600
            or parent.st_uid!=21003 or stat.S_IMODE(parent.st_mode)!=0o700):
        raise PermissionError('live_authority_actual_business_database')
    capacity=os.open(database.with_name(database.name+'.capacity.lock'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    guard=None
    try:
        guard=_open(root,'guard',os.O_RDONLY)
        lock_info=os.fstat(capacity)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid!=21003 or stat.S_IMODE(lock_info.st_mode)!=0o600:
            raise PermissionError('live_authority_capacity_lock')
        _lock(capacity,fcntl.LOCK_EX);_lock(guard,fcntl.LOCK_EX)
        fd=_open(root,'pending.json',os.O_RDONLY)
        with os.fdopen(fd,'rb') as stream:raw=stream.read(2097153)
        marker=decode_json(raw)
        if digest_bytes(raw)!=expected_pending_digest or marker.get('deployment_epoch')!=epoch:
            raise ValueError('live_authority_recovery_marker_changed')
        started=datetime.fromisoformat(marker['started_at'].replace('Z','+00:00'))
        if started.tzinfo is None or not started<=datetime.now(timezone.utc)<end:
            raise ValueError('live_authority_recovery_original_clock')
        class ExistingDatabase:
            def _connect(self):
                db=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=2)
                db.execute('PRAGMA query_only=ON')
                return db
        store=ExistingDatabase()
        with closing(store._connect()) as db:
            db.set_progress_handler(lambda:1 if (end-datetime.now(timezone.utc)).total_seconds()<=60 else 0,10000)
            if db.execute('PRAGMA integrity_check').fetchone()!=('ok',):
                raise ValueError('live_authority_recovery_database_integrity')
            if db.execute('SELECT deployment_epoch FROM trust_state WHERE singleton=1').fetchone()!=(epoch,):
                raise ValueError('live_authority_recovery_database_epoch')
        projection=object.__new__(LiveAuthorityProjection);projection.root=root;projection.epoch=epoch
        # Keep the original marker before replacing the derived current state.
        retained='interrupted-'+expected_pending_digest[7:]+'.json'
        if os.path.lexists(root/retained):raise ValueError('live_authority_recovery_already_attempted')
        projection._write(retained,raw)
        if os.path.lexists(root/'current.pending'):
            partial_fd=_open(root,'current.pending',os.O_RDONLY)
            with os.fdopen(partial_fd,'rb') as stream:partial=stream.read(2097153)
            projection._write('partial-'+expected_pending_digest[7:]+'.json',partial)
            os.unlink(root/'current.pending');_sync(root)
        projection.publish_from(store,clear_pending=False)
        result={'kind':'LiveAuthorityReconciliation','deployment_epoch':epoch,
            'original_pending_digest':expected_pending_digest,'original_deadline':deadline,
            'finished_at':datetime.now(timezone.utc).isoformat(),'model_runs':0,
            'business_state_recreated':False,'qualification_reissued':False}
        result['digest']=digest_jcs(result)
        projection._write('reconciliation-'+expected_pending_digest[7:]+'.json',canonical_json_line(result))
        os.unlink(root/'pending.json');_sync(root)
        return result
    finally:
        if guard is not None:os.close(guard)
        os.close(capacity)
