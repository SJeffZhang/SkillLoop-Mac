"""Proxy-owned physical resource and operation-state archive projection.

The Controller can locate the public completion, but it never opens the live
business database.  An Admin-owned immutable request is consumed by the live
Proxy and the resulting compact database snapshot is granted only to Gate.
"""
from contextlib import closing
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs


class ResourceArchiveInbox:
    def __init__(self,*,store,directory):
        if os.geteuid()!=21003 or 21005 not in set(os.getgroups())|{os.getegid()}:
            raise PermissionError('resource_archive_actual_proxy_with_gate_group')
        self.store=store;self.directory=_directory(directory,21010,21003,0o750);self.seen=set()
        with store._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS campaign_resource_archive_requests('
                'request TEXT PRIMARY KEY,campaign TEXT NOT NULL,state TEXT NOT NULL,projection BLOB)')

    def poll(self):
        names=[]
        with os.scandir(self.directory) as entries:
            for entry in entries:
                if not re.fullmatch(r'[0-9a-f]{64}\.json',entry.name):
                    raise ValueError('resource_archive_request_filename')
                names.append(entry.name)
                if len(names)>6:raise ValueError('resource_archive_request_capacity')
        for name in sorted(names):
            if name in self.seen:continue
            request=read_owned(self.directory/name,uid=21010,gid=21003,limit=262144)
            if request.get('digest')!='sha256:'+name[:-5]:raise ValueError('resource_archive_request_digest')
            if self.export(request) is not None:self.seen.add(name)
            return

    def export(self,request):
        fields={'kind','deployment_epoch','deployment_digest','campaign','config_digest','plan_digest',
            'activation_path','activation_token',
            'deadline','timeout_seconds','maximum_bytes','output_directory','digest'}
        if (set(request)!=fields or request['kind']!='AdminCampaignResourceArchiveProjection'
                or request['deployment_epoch']!=self.store.deployment_epoch
                or type(request['timeout_seconds']) is not int or not 1<=request['timeout_seconds']<=60
                or type(request['maximum_bytes']) is not int or not 1048576<=request['maximum_bytes']<=536870912
                or type(request['activation_token']) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',request['activation_token'])):
            raise ValueError('resource_archive_original_request')
        campaign=request['campaign'];pins=self.store.capacity_campaigns.get(campaign)
        if pins is None or pins['config_digest']!=request['config_digest']:
            raise ValueError('resource_archive_registered_campaign')
        root=_directory(request['output_directory'],21003,21005,0o750)
        target=root/'resource-authority.json';database=root/'authority.sqlite'
        deadline=datetime.fromisoformat(request['deadline'].replace('Z','+00:00'));started=time.monotonic()
        def budget():
            if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline or time.monotonic()-started>=request['timeout_seconds']:
                raise TimeoutError('resource_archive_original_budget')
        budget()
        try:activation=read_owned(request['activation_path'],uid=21001,gid=21003,limit=262144)
        except FileNotFoundError:return None
        if (activation.get('kind')!='CampaignResourceArchiveActivation'
                or activation.get('campaign')!=campaign
                or activation.get('activation_token')!=request['activation_token']
                or activation.get('deployment_epoch')!=self.store.deployment_epoch
                or activation.get('digest')!=digest_jcs({k:v for k,v in activation.items() if k!='digest'})):
            raise ValueError('resource_archive_actual_controller_activation')
        with closing(self.store._connect()) as check:
            prior=check.execute('SELECT state,projection FROM campaign_resource_archive_requests WHERE request=?',
                (request['digest'],)).fetchone()
            runs=check.execute('SELECT state FROM runs WHERE campaign_id=?',(campaign,)).fetchall()
        # The request is provisioned with the deployment, but its actual view
        # is frozen only after every delivered run has a terminal business
        # fence.  Polling before then has no side effect.
        if prior is None and (not runs or any(row[0] in {'active','finalizing'} for row in runs)):
            return None
        if prior is not None:
            if prior[0]!='complete' or prior[1] is None or not target.exists() or not database.exists():
                raise RuntimeError('resource_archive_original_snapshot_unknown_no_reexecution')
            value=decode_json(prior[1])
            if read_owned(target,uid=21003,gid=21005,limit=2097152)!=value:
                raise ValueError('resource_archive_original_projection_changed')
            return value
        # Commit the original intent before any duplicate snapshot could be
        # made.  A crash after this point is preserved as unknown.
        with self.store._transaction() as db:
            deployment=db.execute('SELECT digest,deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
            reservation=db.execute('SELECT plan,generation,disk_bytes,state,committed_at FROM campaign_storage_reservations WHERE campaign=?',(campaign,)).fetchone()
            if (deployment is None or tuple(deployment)!=(request['deployment_digest'],request['deadline'])
                    or reservation is None or tuple(reservation[:4])!=(request['plan_digest'],pins['generation'],pins['disk_bytes'],'reserved')):
                raise ValueError('resource_archive_actual_reservation_binding')
            db.execute("INSERT INTO campaign_resource_archive_requests VALUES(?,?,'started',NULL)",
                (request['digest'],campaign))
        fd=os.open(database,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        try:
            with self.store._writer_lock():
                budget()
                with closing(self.store._connect()) as source,closing(sqlite3.connect(database,timeout=2)) as output:
                    source.set_progress_handler(lambda:(budget() or 0),1000)
                    source.backup(output,pages=64,progress=lambda *_:budget(),sleep=0.01)
                    output.execute('PRAGMA journal_mode=DELETE');output.execute('PRAGMA synchronous=FULL');output.commit()
            info=database.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21003 or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>request['maximum_bytes']):
                raise PermissionError('resource_archive_snapshot_custody_capacity')
            checksum=hashlib.sha256()
            with database.open('r+b') as stream:
                for block in iter(lambda:stream.read(1048576),b''):budget();checksum.update(block)
                os.fchown(stream.fileno(),-1,21005);os.fchmod(stream.fileno(),0o640);os.fsync(stream.fileno())
            with closing(sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
                db.row_factory=sqlite3.Row
                if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
                    raise ValueError('resource_archive_snapshot_integrity')
                reservation=db.execute('SELECT plan,generation,disk_bytes,state,committed_at FROM campaign_storage_reservations WHERE campaign=?',(campaign,)).fetchone()
                cancellations=db.execute('SELECT operation_id,request_digest,committed_at FROM formal_campaign_cancellations WHERE campaign=?',(campaign,)).fetchall()
                runs=db.execute('SELECT run_id,state,fence,task_instance_id FROM runs WHERE campaign_id=? ORDER BY run_id',(campaign,)).fetchall()
                attempts=[]
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_inference_attempts'").fetchone():
                    attempts=db.execute('SELECT i.run_id,i.round_index,i.request_digest,i.response_digest FROM runtime_inference_attempts i JOIN runs r ON r.run_id=i.run_id WHERE r.campaign_id=? ORDER BY i.run_id,i.round_index',(campaign,)).fetchall()
                operations=db.execute('SELECT operation_id,role,run_id,request_digest,method,result_json FROM operations WHERE run_id IN (SELECT run_id FROM runs WHERE campaign_id=?) OR run_id IS NULL ORDER BY operation_id',(campaign,)).fetchall()
                page_size=db.execute('PRAGMA page_size').fetchone()[0];page_count=db.execute('PRAGMA page_count').fetchone()[0]
                freelist=db.execute('PRAGMA freelist_count').fetchone()[0]
            actual_files=[]
            for path in (self.store.path,Path(str(self.store.path)+'-wal')):
                data=path.lstat()
                if not stat.S_ISREG(data.st_mode) or data.st_uid!=21003 or data.st_blocks*512<data.st_size:
                    raise ValueError('resource_archive_actual_allocated_business_file')
                actual_files.append({'name':path.name,'device':data.st_dev,'inode':data.st_ino,
                    'bytes':data.st_size,'allocated_bytes':data.st_blocks*512})
            value={'kind':'ProxyCampaignResourceOwnershipSnapshot','producer_uid':21003,'reader_gid':21005,
                'request_digest':request['digest'],'campaign':campaign,'deployment_epoch':self.store.deployment_epoch,
                'activation_digest':activation['digest'],
                'config_digest':request['config_digest'],'storage_policy':self.store.storage_policy,
                'reservation':dict(reservation),'cancellations':[dict(row) for row in cancellations],
                'runs':[dict(row) for row in runs],
                'inference_attempts':[dict(row) for row in attempts],
                'unknown_inference_attempts':sum(row['response_digest'] is None for row in attempts),
                'operations':[{'operation_id':row['operation_id'],'role':row['role'],'run_id':row['run_id'],
                    'request_digest':row['request_digest'],'method':row['method'],'result_recorded':row['result_json'] is not None}
                    for row in operations],
                'database_files':actual_files,'database_page_size':page_size,'database_page_count':page_count,
                'database_freelist_pages':freelist,'snapshot_database_name':'authority.sqlite',
                'snapshot_database_digest':'sha256:'+checksum.hexdigest(),'snapshot_database_bytes':database.stat().st_size,
                'same_filesystem_device':self.store.path.parent.stat().st_dev,'queue_capacity_verified':True,
                'physical_capacity_verified':True,'resource_release_completed':False,'deletion_authorized':False,
                'exported_at':datetime.now(timezone.utc).isoformat()}
            value['digest']=digest_jcs(value)
            if len(canonical_json_line(value))>2097152:raise ValueError('resource_archive_projection_capacity')
            _publish(target,value,21005)
            with self.store._transaction() as db:
                changed=db.execute("UPDATE campaign_resource_archive_requests SET state='complete',projection=? WHERE request=? AND state='started'",
                    (canonical_json_line(value),request['digest'])).rowcount
                if changed!=1:raise ValueError('resource_archive_original_completion_conflict')
            return value
        except BaseException:
            # Keep the partial database and durable started row. Recovery may
            # inspect them, but cannot silently generate a newer snapshot.
            raise
