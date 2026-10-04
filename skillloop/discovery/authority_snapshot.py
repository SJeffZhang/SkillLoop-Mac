"""Evaluator/Gate read-only view of a Proxy-owned consistent task export."""
from contextlib import closing
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

from skillloop.protocol import decode_json,digest_jcs


class PublicationSnapshot:
    def __init__(self, directory, *, epoch, intent, maximum_bytes):
        if os.geteuid() not in {21004,21005}:
            raise PermissionError('snapshot_observer_role')
        if type(maximum_bytes) is not int or not 1<=maximum_bytes<=9007199254740991:
            raise ValueError('snapshot_frozen_capacity_required')
        if intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'}):
            raise ValueError('snapshot_intent_changed')
        self.directory=Path(directory)
        info=self.directory.lstat()
        if (not self.directory.is_absolute() or self.directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21003
                or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('snapshot_proxy_directory')
        def read(path, limit, content=False):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21003 or info.st_gid!=21004
                        or stat.S_IMODE(info.st_mode)!=0o640 or info.st_size>limit):
                    raise PermissionError('snapshot_private_file')
                if content:return stream.read(limit+1)
                digest=hashlib.sha256()
                for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
                return 'sha256:'+digest.hexdigest(),info.st_size,(info.st_dev,info.st_ino,info.st_mtime_ns)
        manifest=decode_json(read(self.directory/'snapshot.json',262144,True))
        if (manifest['digest']!=digest_jcs({k:v for k,v in manifest.items() if k!='digest'})
                or manifest['kind']!='ProxyCompletedTaskSnapshot' or manifest['deployment_epoch']!=epoch
                or manifest['intent_digest']!=intent['digest'] or manifest['exporter_uid']!=21003
                or manifest['run_request_digest']!=intent['run_request']['digest']
                or manifest['task_binding_digest']!=intent['binding']['digest']):
            raise ValueError('snapshot_actual_task_binding')
        exported=datetime.fromisoformat(manifest['exported_at'].replace('Z','+00:00'))
        if (exported.tzinfo is None or exported>datetime.now(timezone.utc)
                or type(manifest['export_timeout_seconds']) is not int
                or not 1<=manifest['export_timeout_seconds']<=60
                or type(manifest['export_elapsed_seconds']) not in (int,float)
                or not 0<=manifest['export_elapsed_seconds']<=manifest['export_timeout_seconds']):
            raise ValueError('snapshot_original_export_clock')
        self.path=self.directory/'authority.db'
        digest,size,self.identity=read(self.path,maximum_bytes)
        if digest!=manifest['database_digest'] or size!=manifest['database_size_bytes']:
            raise ValueError('snapshot_database_digest')
        self.task=manifest['task_instance_id'];self.manifest=manifest
        with closing(self.connect()) as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise ValueError('snapshot_integrity')
            from skillloop.proxy.snapshot_content import snapshot_content_digest
            if (manifest.get('consistent_export_compacted') is not True
                    or snapshot_content_digest(db,lambda:None)!=manifest.get('database_content_digest')):
                raise ValueError('snapshot_complete_content_identity')
            task=db.execute('SELECT run_request_digest,binding_digest,approval_digest FROM tasks WHERE task_instance_id=?',(self.task,)).fetchone()
            run=db.execute('SELECT state,fence FROM runs WHERE task_instance_id=?',(self.task,)).fetchone()
            if (tuple(task or ())!=(manifest['run_request_digest'],manifest['task_binding_digest'],manifest['approval_digest'])
                    or tuple(run or ())!=('cancelled',manifest['cancellation_fence'])):
                raise ValueError('snapshot_actual_authority_task')

    def connect(self):
        info=self.path.lstat()
        if (info.st_dev,info.st_ino,info.st_mtime_ns)!=self.identity:
            raise ValueError('snapshot_changed_after_verification')
        db=sqlite3.connect(self.path.absolute().as_uri()+'?mode=ro&immutable=1',uri=True)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        return db

    def inspect_publication_proof(self, task_instance_id):
        if task_instance_id!=self.task:raise PermissionError('snapshot_foreign_task')
        with closing(self.connect()) as db:
            publication=db.execute('SELECT * FROM publications WHERE task_instance_id=?',(self.task,)).fetchone()
            if publication is None:return None
            grant=db.execute('SELECT * FROM grants WHERE grant_ref=?',(publication['grant_ref'],)).fetchone()
            receipt=db.execute('SELECT * FROM receipts WHERE receipt_id=?',(grant['receipt_id'],)).fetchone() if grant else None
            return {'publication':dict(publication),'grant':dict(grant) if grant else None,
                    'receipt':dict(receipt) if receipt else None}

    def inspect_terminal_output(self, run_id):
        with closing(self.connect()) as db:
            run=db.execute('SELECT task_instance_id FROM runs WHERE run_id=?',(run_id,)).fetchone()
            if run is None or run[0]!=self.task:raise PermissionError('snapshot_foreign_terminal')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='terminal_outputs'").fetchone():
                return None
            value=db.execute('SELECT * FROM terminal_outputs WHERE run_id=?',(run_id,)).fetchone()
            return dict(value) if value else None
