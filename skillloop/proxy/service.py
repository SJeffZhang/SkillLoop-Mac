"""Formal Proxy process: administrator-provisioned catalog and frozen role sockets.

This internal deployment entry runs as UID 21003. It never accepts package paths
or caller-declared roles, and does not start a model or manufacture a campaign.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import re
from pathlib import Path
import signal
import stat
import sqlite3
from contextlib import closing
import threading
import time

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs, digest_bytes, ProtocolError
from skillloop.proxy.approval import ApprovalAuthority
from skillloop.proxy.server import ProxyServer
from skillloop.proxy.store import ProxyStore, ProxyError
from skillloop.proxy.task_admission import ControllerTaskAdmission, deployment_deadline


def deployment(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or path.parent.is_symlink():
        raise PermissionError('proxy_deployment_path')
    parent = path.parent.lstat()
    if (parent.st_uid != 21010 or parent.st_gid != 21003
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise PermissionError('proxy_deployment_admin_directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 21010
                or info.st_gid != 21003 or stat.S_IMODE(info.st_mode) != 0o640
                or info.st_size > 2097152):
            raise PermissionError('proxy_deployment_admin_file')
        raw = stream.read(2097153)
    if len(raw) > 2097152:
        raise ValueError('proxy_deployment_size')
    value = decode_json(raw)
    required = {'kind', 'deployment_epoch', 'database', 'socket_directory', 'catalog', 'deadline', 'digest',
                'admitted_campaigns', 'task_directory', 'task_receipt_directory', 'snapshot_directory', 'snapshot_timeout_seconds', 'storage_policy', 'authority_projection_directory'}
    if (type(value) is not dict or not required<=set(value)
            or set(value)-required-{'plan_revision_directory','source_repositories', 'private_task_transport','source_archive_directory','inference_socket_directory'}
            or value['kind'] != 'ProxyServiceDeployment'
            or value['digest'] != digest_jcs({k: v for k, v in value.items() if k != 'digest'})
            or type(value['deployment_epoch']) is not str or not 1 <= len(value['deployment_epoch']) <= 256
            or type(value['catalog']) is not dict
            or set(value['catalog']) != {'domains', 'configurations', 'factories'}
            or any(type(records) is not dict or not 1 <= len(records) <= 128 for records in value['catalog'].values())):
        raise ValueError('proxy_deployment_shape')
    for field in ('database', 'socket_directory', 'task_directory', 'task_receipt_directory', 'snapshot_directory', 'authority_projection_directory',
                  *(['plan_revision_directory'] if 'plan_revision_directory' in value else []),
                  *(['source_archive_directory'] if 'source_archive_directory' in value else []),
                  *(['inference_socket_directory'] if 'inference_socket_directory' in value else [])):
        if type(value[field]) is not str or not Path(value[field]).is_absolute():
            raise ValueError('proxy_deployment_absolute_path')
    deadline = deployment_deadline(value['deadline'])
    if deadline.tzinfo is None or not 22 < (deadline - datetime.now(timezone.utc)).total_seconds() <= 28800:
        raise ValueError('proxy_deployment_frozen_deadline')
    if type(value['snapshot_timeout_seconds']) is not int or not 1<=value['snapshot_timeout_seconds']<=60:
        raise ValueError('snapshot_frozen_timeout')
    if (deadline-datetime.now(timezone.utc)).total_seconds()<=44+value['snapshot_timeout_seconds']:
        raise ValueError('proxy_original_terminal_reserve_required')
    private = value.get('private_task_transport')
    if private is not None and (type(private) is not dict or set(private) != {'inbox', 'receipts'}
            or any(type(p) is not str or not Path(p).is_absolute() for p in private.values())
            or len(set(private.values())) != 2
            or set(private.values()) & {value['task_directory'], value['task_receipt_directory']}):
        raise ValueError('proxy_private_transport_separate_paths')
    if value.get('inference_socket_directory') in {value['database'], value['socket_directory']}:
        raise ValueError('proxy_separate_inference_endpoint')
    return value, deadline


class PlanRevisionInbox:
    """Read-only Admin catalog/plan handoff; grants live in the business DB."""
    def __init__(self,admission,directory):
        self.admission=admission;self.directory=Path(directory);self.seen=set()
        info=self.directory.lstat()
        if (not self.directory.is_absolute() or self.directory.is_symlink()
                or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21010
                or info.st_gid!=21003 or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('plan_revision_admin_directory')

    def poll(self):
        with os.scandir(self.directory) as entries:
            names=[]
            for entry in entries:
                if not re.fullmatch(r'[0-9a-f]{64}\.json',entry.name):
                    raise ValueError('plan_revision_immutable_filename')
                names.append(entry.name)
                if len(names)>108:raise ValueError('plan_revision_inbox_capacity')
        # Revisions can arrive in arbitrary digest order. Apply exactly one
        # whose original parent is current; other parents remain pending.
        pending=[]
        for name in sorted(names):
            if name in self.seen:continue
            from skillloop.discovery.formal_task_gate import read_owned
            value=read_owned(self.directory/name,uid=21010,gid=21003,limit=2097152)
            if value['digest']!='sha256:'+name[:-5]:raise ValueError('plan_revision_filename_digest')
            if value.get('kind') not in {'AdminCampaignSourceAdmission','AdminCampaignPlanRevision'}:
                raise ValueError('plan_revision_admin_handoff_kind')
            pending.append((value['kind']!='AdminCampaignSourceAdmission',name,value))
        for _,name,value in sorted(pending,key=lambda item:(item[0],item[1])):
            try:
                if value['kind']=='AdminCampaignSourceAdmission':self.admission.authorize_source(self.directory/name)
                else:self.admission.revise_plan(self.directory/name)
            except ProxyError as error:
                if error.code in {'version_conflict','queue_full'}:continue
                raise
            self.seen.add(name)
            return


class TaskProvisioningInbox:
    """Bounded trusted file transport; no extension to frozen RPC methods.

    Controller publishes immutable digest-named files after actual approval.
    Proxy publishes original admission receipts, including explicit rejections.
    Runtime has neither directory. DB commit precedes receipt publication, so a
    service restart recovers the same receipt without staging a second task.
    """
    def __init__(self, admission, directory, receipt_directory, *, private=False):
        self.admission = admission
        self.directory = Path(directory)
        self.receipts = Path(receipt_directory)
        self.seen = set()
        self.private = private
        self.reader = 21004 if private else 21001
        for path, uid, gid in ((self.directory, self.reader, 21003), (self.receipts, 21003, self.reader)):
            info = path.lstat()
            if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                    or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750):
                raise PermissionError('task_inbox_custody')

    def poll(self):
        # Stop enumeration itself at the campaign-wide 3 * 128 reserved maximum.
        with os.scandir(self.directory) as entries:
            names = []
            for entry in entries:
                names.append(entry.name)
                if len(names) > (768 if self.private else 384):
                    raise ValueError('task_inbox_capacity')
        for name in sorted(names):
            if self.private and re.fullmatch(r'[0-9a-f]{64}\.pending', name):
                continue  # Evaluator publishes only after fsync and atomic rename.
            if not re.fullmatch(r'[0-9a-f]{64}\.json', name):
                raise ValueError('task_inbox_filename')
            if name in self.seen:
                continue
            target = self.receipts / name
            if os.path.lexists(target):
                # Restart authenticates the durable effect, not just a file's
                # ownership. A corrupt accepted receipt must never skip work
                # or invent a committed admission after a service restart.
                from skillloop.discovery.formal_task_gate import read_owned
                saved=read_owned(target,uid=21003,gid=self.reader,limit=262144)
                ok=saved.get('ok')
                fields={'kind','intent_digest','deployment_epoch','ok','digest',
                        'result' if ok is True else 'error_code'}
                if (type(ok) is not bool or set(saved)!=fields
                        or saved.get('kind')!='TaskAdmissionTransportReceipt'
                        or saved.get('intent_digest')!='sha256:'+name[:-5]
                        or saved.get('deployment_epoch')!=self.admission.store.deployment_epoch):
                    raise ValueError('task_receipt_restart_identity')
                if self.private:
                    raw = self.admission.committed_receipt(saved['intent_digest'])
                    committed = None if raw is None else (raw,)
                else:
                    with closing(self.admission.store._connect()) as db:
                        committed=db.execute('SELECT receipt FROM controller_task_admissions WHERE intent=?',
                            (saved['intent_digest'],)).fetchone()
                if ok:
                    if committed is None or decode_json(committed[0])!=saved['result']:
                        raise ValueError('task_receipt_not_actual_committed_admission')
                elif (committed is not None or type(saved['error_code']) is not str
                        or not 1<=len(saved['error_code'])<=128):
                    raise ValueError('task_rejection_conflicts_with_committed_admission')
                self.seen.add(name)
                continue
            try:
                receipt = self.admission.admit(self.directory / name, expected_digest='sha256:' + name[:-5])
                result = {'ok': True, 'result': receipt}
            except ProxyError as error:
                result = {'ok': False, 'error_code': error.code}
            except PermissionError:
                result = {'ok': False, 'error_code': 'denied'}
            except (ValueError, ProtocolError, KeyError, TypeError):
                result = {'ok': False, 'error_code': 'invalid_args'}
            result.update(kind='TaskAdmissionTransportReceipt', intent_digest='sha256:' + name[:-5],
                          deployment_epoch=self.admission.store.deployment_epoch)
            result['digest'] = digest_jcs(result)
            # Storage errors propagate: they are not proof of uncommitted work.
            temporary = self.receipts / (name + '.pending')
            if os.path.lexists(temporary):
                fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 21003 or info.st_gid != self.reader
                            or stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > 262144
                            or stream.read(262145) != canonical_json_line(result)):
                        raise RuntimeError('task_receipt_pending_unknown_preserve_evidence')
                os.rename(temporary,target)
                directory_fd=os.open(self.receipts,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(directory_fd)
                finally:os.close(directory_fd)
                self.seen.add(name)
                continue
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), -1, self.reader)
                os.fchmod(stream.fileno(), 0o640)
                stream.write(canonical_json_line(result))
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(temporary, target)
            directory_fd = os.open(self.receipts, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.seen.add(name)
            return  # One new admission per tick; keep role RPCs responsive.


class CompletedTaskSnapshots:
    """Proxy-only consistent export after actual Controller cancellation.

    Snapshots are private evaluator/Gate evidence, never Controller/Runtime
    mounts. The shared service remains alive; each snapshot is immutable and
    includes the issuing approval and task admission from the business DB.
    A failed/partial export is preserved and stops the round, not retried.
    """
    def __init__(self, store, directory, *, deadline, timeout_seconds):
        if os.geteuid()!=21003:raise PermissionError('snapshot_proxy_uid_required')
        self.deadline=deadline;self.timeout=timeout_seconds
        self.store=store;self.directory=Path(directory);self.exported=set()
        self.thread=None;self.failure=None;self.stopping=False
        self.wakeup=threading.Event()
        info=self.directory.lstat()
        if (self.directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21003
                or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('snapshot_evaluator_directory_grant')

    def start(self):
        if self.thread is not None:raise RuntimeError('snapshot_worker_already_started')
        def work():
            try:
                while True:
                    self.wakeup.wait()
                    self.wakeup.clear()
                    self.poll()
                    if self.stopping:return
            except BaseException as error:self.failure=error
        self.thread=threading.Thread(target=work,name='proxy-private-snapshot-export',daemon=False)
        self.thread.start()
        self.wakeup.set()  # Recover committed cancellations after process restart.

    def wake(self):
        self.wakeup.set()

    def tick(self):
        if self.failure is not None:
            raise RuntimeError('snapshot_export_failed_preserve_custody') from self.failure

    def close(self):
        self.stopping=True;self.wakeup.set()
        if self.thread is not None:
            remaining=max(0,(self.deadline-datetime.now(timezone.utc)).total_seconds())
            self.thread.join(timeout=min(self.timeout+1,remaining))
            if self.thread.is_alive():raise RuntimeError('snapshot_export_still_running_preserve_custody')
        if self.failure is not None:
            raise RuntimeError('snapshot_export_failed_preserve_custody') from self.failure

    def poll(self):
        with closing(self.store._connect()) as db:
            rows=list(db.execute("SELECT a.intent,a.receipt,t.task_instance_id,t.run_request_digest,t.binding_digest,t.approval_digest,r.run_id,r.fence FROM controller_task_admissions a JOIN tasks t ON t.task_instance_id=a.task JOIN runs r ON r.run_id=t.run_id WHERE r.state='cancelled'"))
        if len(rows)>384:raise ValueError('snapshot_campaign_capacity')
        for row in rows:
            key=row['intent']
            if key in self.exported:continue
            directory=self.directory/key[7:]
            if os.path.lexists(directory):
                # Recover only a complete, original immutable export. No copy,
                # new timestamp, manifest rewrite, or partial export retry.
                self._recover_complete(directory,row)
                self.exported.add(key)
                continue
            started=time.monotonic()
            def within_budget(*_args):
                if (time.monotonic()-started>self.timeout or
                        (self.deadline-datetime.now(timezone.utc)).total_seconds()<=22):
                    raise TimeoutError('snapshot_original_budget_expired')
            within_budget()
            directory.mkdir(mode=0o750)
            os.chown(directory,-1,21004);os.chmod(directory,0o750)
            target=directory/'authority.db'
            # VACUUM INTO creates a consistent compact export directly. A
            # backup followed by VACUUM first copied every physically reserved
            # free page from the live authority DB for every completed task.
            # Keep the actual live reservation intact and never retry a partial
            # target. The evaluator cannot read it until custody is published.
            with closing(self.store._connect()) as source:
                page_size=source.execute('PRAGMA page_size').fetchone()[0]
                source_pages=source.execute('PRAGMA page_count').fetchone()[0]
                if (page_size!=4096 or not 1<=source_pages<=131072):
                    raise ValueError('snapshot_actual_source_capacity')
                # Reserve a conservative two full live-DB upper bounds for
                # SQLite's sorting/export peak, rather than claiming that the
                # small final compact file bounds temporary storage as well.
                peak_bytes=2*source_pages*page_size
                free=os.statvfs(directory)
                if free.f_bavail*free.f_frsize<2147483648+peak_bytes:
                    raise OSError('snapshot_actual_export_peak_free_floor')
                def sql_budget():
                    within_budget()
                    available=os.statvfs(directory)
                    if available.f_bavail*available.f_frsize<2147483648:
                        raise OSError('snapshot_actual_export_free_floor')
                    if os.path.lexists(target) and target.lstat().st_size>source_pages*page_size:
                        raise ValueError('snapshot_export_original_capacity_exceeded')
                    return 0
                source.set_progress_handler(sql_budget,1000)
                try:source.execute('VACUUM main INTO ?', (str(target),))
                finally:source.set_progress_handler(None,0)
            fd=os.open(target,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                info=os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=21003
                        or not 1<=info.st_size<=source_pages*page_size):
                    raise PermissionError('snapshot_actual_export_custody')
                os.fchown(fd,-1,21004);os.fchmod(fd,0o640);os.fsync(fd)
            finally:os.close(fd)
            with closing(sqlite3.connect(target.absolute().as_uri()+'?mode=ro&immutable=1',uri=True)) as output:
                output.set_progress_handler(lambda: (within_budget() or 0),1000)
                if (output.execute('PRAGMA integrity_check').fetchone()!=('ok',)
                        or output.execute('PRAGMA freelist_count').fetchone()!=(0,)):
                    raise RuntimeError('snapshot_actual_compact_database_integrity')
                run=output.execute('SELECT state,fence FROM runs WHERE run_id=?',(row['run_id'],)).fetchone()
                admission=output.execute('SELECT receipt FROM controller_task_admissions WHERE intent=?',(key,)).fetchone()
                if run!=('cancelled',row['fence']) or admission is None or admission[0]!=row['receipt']:
                    raise RuntimeError('snapshot_committed_task_binding')
                from skillloop.proxy.snapshot_content import snapshot_content_digest
                content_digest=snapshot_content_digest(output,within_budget)
            with target.open('rb') as stream:os.fsync(stream.fileno())
            import hashlib
            h=hashlib.sha256()
            with target.open('rb') as stream:
                for block in iter(lambda:stream.read(1048576),b''):
                    within_budget();h.update(block)
            manifest={'kind':'ProxyCompletedTaskSnapshot','deployment_epoch':self.store.deployment_epoch,
                'intent_digest':key,'task_instance_id':row['task_instance_id'],'run_id':row['run_id'],
                'run_request_digest':row['run_request_digest'],'task_binding_digest':row['binding_digest'],
                'approval_digest':row['approval_digest'],'cancellation_fence':row['fence'],
                'admission_receipt_digest':decode_json(row['receipt'])['digest'],
                'database_digest':'sha256:'+h.hexdigest(),'database_size_bytes':target.stat().st_size,
                'consistent_export_compacted':True,'database_content_digest':content_digest,
                'export_method':'sqlite_vacuum_into','source_page_count':source_pages,
                'source_page_size':page_size,'export_peak_bound_bytes':peak_bytes,
                'exporter_uid':21003,'exported_at':datetime.now(timezone.utc).isoformat(),
                'export_elapsed_seconds':time.monotonic()-started, 'export_timeout_seconds':self.timeout,
                'model_stop_verified':False,'independent_gate_verified':False}
            manifest['digest']=digest_jcs(manifest)
            pending=directory/'snapshot.pending'
            fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(),-1,21004);os.fchmod(stream.fileno(),0o640)
                stream.write(canonical_json_line(manifest));stream.flush();os.fsync(stream.fileno())
            within_budget()
            os.rename(pending,directory/'snapshot.json')
            for root in (directory,self.directory):
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            self.exported.add(key)

    def _recover_complete(self,directory,row):
        import hashlib
        started=time.monotonic()
        def within_budget():
            if (time.monotonic()-started>self.timeout or
                    (self.deadline-datetime.now(timezone.utc)).total_seconds()<=22):
                raise TimeoutError('snapshot_recovery_original_budget_expired')
        info=directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid!=21003
                or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('snapshot_recovery_directory_custody')
        if set(os.listdir(directory))!={'authority.db','snapshot.json'}:
            raise RuntimeError('snapshot_partial_export_preserve_evidence')
        def read(path,limit=None):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                data=os.fstat(stream.fileno())
                if (not stat.S_ISREG(data.st_mode) or data.st_uid!=21003 or data.st_gid!=21004
                        or stat.S_IMODE(data.st_mode)!=0o640 or data.st_nlink!=1 or (limit is not None and data.st_size>limit)):
                    raise PermissionError('snapshot_recovery_file_custody')
                if limit is not None:return stream.read(limit+1)
                h=hashlib.sha256()
                for block in iter(lambda:stream.read(1048576),b''):
                    within_budget();h.update(block)
                return 'sha256:'+h.hexdigest(),data.st_size
        manifest=decode_json(read(directory/'snapshot.json',262144))
        expected={'kind':'ProxyCompletedTaskSnapshot','deployment_epoch':self.store.deployment_epoch,
            'intent_digest':row['intent'],'task_instance_id':row['task_instance_id'],
            'run_id':row['run_id'],'run_request_digest':row['run_request_digest'],
            'task_binding_digest':row['binding_digest'],'approval_digest':row['approval_digest'],
            'cancellation_fence':row['fence'],'admission_receipt_digest':decode_json(row['receipt'])['digest'],
            'exporter_uid':21003,'model_stop_verified':False,'independent_gate_verified':False,
            'export_timeout_seconds':self.timeout,'consistent_export_compacted':True,
            'export_method':'sqlite_vacuum_into','source_page_size':4096}
        if (manifest.get('digest')!=digest_jcs({k:v for k,v in manifest.items() if k!='digest'})
                or any(manifest.get(k)!=v for k,v in expected.items())):
            raise ValueError('snapshot_recovery_original_manifest_binding')
        exported=datetime.fromisoformat(manifest['exported_at'].replace('Z','+00:00'))
        elapsed=manifest['export_elapsed_seconds']
        if (exported.tzinfo is None or exported>datetime.now(timezone.utc) or exported>=self.deadline
                or type(elapsed) not in (int,float) or not 0<=elapsed<=self.timeout):
            raise ValueError('snapshot_recovery_original_clock_invalid')
        digest,size=read(directory/'authority.db')
        if (digest!=manifest['database_digest'] or size!=manifest['database_size_bytes']
                or type(manifest.get('source_page_count')) is not int
                or not 1<=manifest['source_page_count']<=131072
                or manifest.get('export_peak_bound_bytes')!=2*manifest['source_page_count']*4096
                or size>manifest['source_page_count']*4096):
            raise ValueError('snapshot_recovery_original_database_digest')
        within_budget()
        uri=(directory/'authority.db').absolute().as_uri()+'?mode=ro&immutable=1'
        with closing(sqlite3.connect(uri,uri=True)) as db:
            from skillloop.proxy.snapshot_content import snapshot_content_digest
            if snapshot_content_digest(db,within_budget)!=manifest.get('database_content_digest'):
                raise ValueError('snapshot_recovery_complete_content_changed')
            db.set_progress_handler(lambda:1 if time.monotonic()-started>self.timeout else 0,1000)
            if (db.execute('PRAGMA integrity_check').fetchone()!=('ok',)
                    or db.execute('PRAGMA freelist_count').fetchone()!=(0,)):
                raise ValueError('snapshot_recovery_database_integrity')
            task=db.execute('SELECT run_request_digest,binding_digest,approval_digest FROM tasks WHERE task_instance_id=?',(row['task_instance_id'],)).fetchone()
            run=db.execute('SELECT state,fence FROM runs WHERE run_id=?',(row['run_id'],)).fetchone()
            admission=db.execute('SELECT receipt FROM controller_task_admissions WHERE intent=?',(row['intent'],)).fetchone()
            if (task!=(row['run_request_digest'],row['binding_digest'],row['approval_digest'])
                    or run!=('cancelled',row['fence']) or admission!=(row['receipt'],)):
                raise ValueError('snapshot_recovery_committed_database_binding')
        within_budget()


def main():
    if os.geteuid() != 21003:
        raise PermissionError('proxy_role_required')
    os.umask(0o077)
    config, deadline = deployment(os.environ['SKILLLOOP_PROXY_DEPLOYMENT'])
    database = Path(config['database'])
    directory = Path(config['socket_directory'])
    # Bootstrap must provision the mount roots; the service never chowns them.
    parent = database.parent.lstat()
    sockets = directory.lstat()
    if (database.is_symlink() or database.parent.is_symlink() or directory.is_symlink()
            or parent.st_uid != 21003 or stat.S_IMODE(parent.st_mode) != 0o700
            or sockets.st_uid != 21003 or stat.S_IMODE(sockets.st_mode) != 0o711
            or not {21001, 21002, 21004, 21010}.issubset(set(os.getgroups()) | {os.getegid()})):
        raise PermissionError('proxy_storage_or_socket_provisioning')
    from skillloop.proxy.storage import FormalStorageStore
    reconciliation=os.environ.get('SKILLLOOP_AUTHORITY_RECONCILIATION')
    if reconciliation:
        from skillloop.discovery.formal_task_gate import read_owned
        from skillloop.proxy.qualification_authority import reconcile_interrupted
        authorization=read_owned(reconciliation,uid=21010,gid=21003,limit=262144)
        if (set(authorization)!={'kind','deployment_digest','pending_digest','deadline','digest'}
                or authorization['kind']!='AuthorityProjectionRecoveryAuthorization'
                or authorization['deployment_digest']!=config['digest']
                or authorization['deadline']!=config['deadline']):
            raise ValueError('authority_reconciliation_exact_admin_authorization')
        reconcile_interrupted(config['authority_projection_directory'],database,
            epoch=config['deployment_epoch'],expected_pending_digest=authorization['pending_digest'],
            deadline=config['deadline'])
    store = FormalStorageStore(database, deployment_epoch=config['deployment_epoch'],
        policy=config['storage_policy'],campaigns=config['admitted_campaigns'],
        authority_projection_directory=config['authority_projection_directory'],
        snapshot_directory=config['snapshot_directory'])
    authority = ApprovalAuthority(store, **config['catalog'])
    admission = ControllerTaskAdmission(store, admitted_campaigns=config['admitted_campaigns'],
        source_repositories=config.get('source_repositories'))
    inbox = TaskProvisioningInbox(admission, config['task_directory'], config['task_receipt_directory'])
    private_inbox = None
    if 'private_task_transport' in config:
        from skillloop.proxy.private_admission import EvaluatorTaskAdmission
        transport = config['private_task_transport']
        private_inbox = TaskProvisioningInbox(EvaluatorTaskAdmission(admission),
            transport['inbox'], transport['receipts'], private=True)
    snapshots = CompletedTaskSnapshots(store, config['snapshot_directory'],deadline=deadline,
                                       timeout_seconds=config['snapshot_timeout_seconds'])
    with store._transaction() as db:
        db.execute('CREATE TABLE IF NOT EXISTS formal_proxy_deployment(singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL, deadline TEXT NOT NULL)')
        prior = db.execute('SELECT digest,deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
        if prior and tuple(prior) != (config['digest'], config['deadline']):
            raise ValueError('proxy_deployment_changed_requires_new_epoch')
        db.execute('INSERT OR IGNORE INTO formal_proxy_deployment VALUES(1,?,?)', (config['digest'], config['deadline']))
    revisions=(PlanRevisionInbox(admission,config['plan_revision_directory'])
               if 'plan_revision_directory' in config else None)
    from skillloop.proxy.archive_projection import SourceArchiveInbox
    source_archives=(SourceArchiveInbox(store=store,admission=admission,authority=authority,
        directory=config['source_archive_directory']) if 'source_archive_directory' in config else None)
    inference_authority = None
    if 'inference_socket_directory' in config:
        from skillloop.proxy.inference_authority import RuntimeInferenceAuthority
        inference_authority = RuntimeInferenceAuthority(store)
    try:
        with ProxyServer(store, directory, controller_uid=21001, runtime_uid=21002,
                         controller_gid=21001, runtime_gid=21002, approval_authority=authority,
                         admin_gid=21010,on_cancel=snapshots.wake,inference_authority=inference_authority,
                         inference_directory=config.get('inference_socket_directory')) as server:
            old_handlers = {};timer=None
            def stop(_signum=None, _frame=None):
                server.stop()
            try:
                snapshots.start()
                for signum in (signal.SIGTERM, signal.SIGINT):
                    old_handlers[signum] = signal.signal(signum, stop)
                # Keep the original wall clock: reserve in-flight drain (22s),
                # one bounded final snapshot, and its final safety/export window.
                reserve=44+config['snapshot_timeout_seconds']
                timer=threading.Timer(max(0,(deadline-datetime.now(timezone.utc)).total_seconds()-reserve),stop)
                timer.start()
                def provision():
                    if revisions is not None:revisions.poll()
                    if source_archives is not None:source_archives.poll()
                    inbox.poll()
                    if private_inbox is not None: private_inbox.poll()
                    snapshots.tick()
                server.serve_forever(provisioning_poll=provision)
            finally:
                server.stop()
                if timer is not None:timer.cancel()
                for signum,old in old_handlers.items():signal.signal(signum,old)
        # ProxyServer has drained accepted RPCs before final snapshot drain.
    finally:
        import sys
        primary=sys.exc_info()[1]
        try:snapshots.close()
        except BaseException as error:
            if primary is None:raise
            primary.add_note('snapshot_shutdown_error:'+type(error).__name__)
        finally:
            try:store.close()
            except BaseException as error:
                if primary is None:raise
                primary.add_note('storage_shutdown_error:'+type(error).__name__)


if __name__ == '__main__':
    main()
