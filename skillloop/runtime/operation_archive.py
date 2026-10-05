"""Controller preserves actual operation recovery and readable dev history.

Protected role stores are excluded. This does not certify physical campaign
capacity or permit evidence deletion.
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
from skillloop.protocol import digest_jcs
from skillloop.runtime.operation_store import OperatorOperationStore
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest


def preserve_operation_history(*,policy_path,journal_directory,store,ledger,whole_round_manifest_path):
    if os.geteuid()!=21001 or type(store) is not OperatorOperationStore:
        raise PermissionError('operation_archive_actual_controller_store')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=2097152)
    fields={'kind','campaign','deployment_epoch','config_digest','output_directory','sources',
            'maximum_bytes','maximum_files','timeout_seconds','deadline','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenControllerOperationArchive'
            or type(policy['sources']) is not list or not 1<=len(policy['sources'])<=64
            or type(policy['maximum_bytes']) is not int or not 1048576<=policy['maximum_bytes']<=268435456
            or type(policy['maximum_files']) is not int or not 1<=policy['maximum_files']<=4096
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=120):
        raise ValueError('operation_archive_frozen_original_cost')
    whole=read_round_manifest(whole_round_manifest_path)
    if whole['deployment_epoch']!=policy['deployment_epoch'] or store.epoch!=policy['deployment_epoch'] or not any(c['campaign_digest']==policy['campaign'] for c in whole['campaigns']):
        raise ValueError('operation_archive_original_round_identity')
    expiry=datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'));started=time.monotonic()
    if ledger.campaign_started_at is None or expiry.timestamp()!=ledger.campaign_started_at+28800:
        raise ValueError('operation_archive_original_campaign_clock')
    root=_directory(policy['output_directory'],21001,21005,0o750)
    journal=_directory(journal_directory,21001,21001,0o700)
    if any(root.iterdir()) or any(journal.iterdir()):raise RuntimeError('operation_archive_partial_original_preserved')
    if (expiry-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+60:
        raise TimeoutError('operation_archive_original_remaining_budget')
    cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign'],stage='resource_archive_restore',
        operation_key='operation-archive-'+policy['digest'][7:],seconds=policy['timeout_seconds']+60,
        input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_bytes'])
    _save(journal,'intent.json',{'kind':'ControllerOperationArchiveIntent','policy_digest':policy['digest'],'spending':cost})
    used=0;files=[];locks=[];count=0
    def budget():
        if time.monotonic()-started>=policy['timeout_seconds'] or datetime.now(timezone.utc)>=expiry:
            raise TimeoutError('operation_archive_original_clock')
    def capacity(size):
        if used+size+1048576>policy['maximum_bytes']:raise ValueError('operation_archive_original_capacity')
    def snapshot_database():
        target=root/'operations.sqlite';fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        with closing(sqlite3.connect(target,timeout=2)) as destination:
            destination.execute('PRAGMA journal_mode=DELETE');destination.execute('PRAGMA synchronous=FULL')
            def progress(*_):budget();capacity(target.stat().st_size)
            with closing(sqlite3.connect(store.path.as_uri()+'?mode=ro',uri=True,timeout=2)) as source:
                source.backup(destination,pages=64,progress=progress,sleep=0.01)
            destination.set_progress_handler(lambda:int(time.monotonic()-started>=policy['timeout_seconds']),1000)
            if destination.execute('PRAGMA integrity_check').fetchall()!=[('ok',)] or destination.execute('SELECT version,epoch FROM identity').fetchall()!=[(1,policy['deployment_epoch'])]:
                raise ValueError('operation_archive_actual_store_integrity')
        return target
    database=snapshot_database()
    checksum=hashlib.sha256()
    with database.open('r+b') as stream:
        for block in iter(lambda:stream.read(1048576),b''):budget();checksum.update(block)
        os.fchown(stream.fileno(),-1,21005);os.fchmod(stream.fileno(),0o640);os.fsync(stream.fileno())
    used=database.stat().st_size
    database_pin={'name':'operations.sqlite','bytes':used,'digest':'sha256:'+checksum.hexdigest()}
    aliases=set()
    for source in policy['sources']:
        budget()
        if (set(source)!={'alias','path','uid','gid','mode'} or type(source['alias']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',source['alias']) or source['alias'] in aliases
                or source['uid'] not in {21001,21006,21007,21011}
                or source['gid']!=21001 or source['mode']!=(0o700 if source['uid']==21001 else 0o750)):
            raise PermissionError('operation_archive_no_protected_role_grant')
        aliases.add(source['alias']);origin=_directory(source['path'],source['uid'],source['gid'],source['mode'])
        if origin==root or origin in root.parents or root in origin.parents:
            raise ValueError('operation_archive_disjoint_original_roots')
        pending=[origin]
        while pending:
            parent=pending.pop();before_directory=parent.stat()
            with os.scandir(parent) as entries:children=sorted(entries,key=lambda e:e.name)
            for child in children:
                budget();count+=1
                if count>policy['maximum_files']:raise ValueError('operation_archive_file_count')
                path=Path(child.path);before=child.stat(follow_symlinks=False)
                if (before.st_uid!=source['uid'] or not (stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode))):
                    raise PermissionError('operation_archive_original_owner')
                if stat.S_ISDIR(before.st_mode):
                    if before.st_gid!=source['gid'] or stat.S_IMODE(before.st_mode)!=source['mode']:
                        raise PermissionError('operation_archive_original_directory')
                    pending.append(path);continue
                if child.name=='spending.lock' and source['uid'] in {21006,21007}:
                    if before.st_size!=0 or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600:
                        raise PermissionError('operation_archive_original_lock_metadata')
                    locks.append({'source':source['alias'],'path':path.relative_to(origin).as_posix(),
                                  'uid':before.st_uid,'gid':before.st_gid,'bytes':0});continue
                if (before.st_nlink!=1 or before.st_gid!=source['gid']
                        or stat.S_IMODE(before.st_mode)!=(0o600 if source['uid']==21001 else 0o640)):
                    raise PermissionError('operation_archive_original_file_grant')
                capacity(before.st_size)
                relative=source['alias']+'/'+path.relative_to(origin).as_posix()
                if len(relative)>1024:raise ValueError('operation_archive_relative_path_capacity')
                name='history-'+hashlib.sha256(relative.encode()).hexdigest()+'.bin'
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);out=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
                checksum=hashlib.sha256();size=0
                with os.fdopen(fd,'rb') as reader,os.fdopen(out,'wb') as writer:
                    opened=os.fstat(reader.fileno())
                    if (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)!=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns):raise ValueError('operation_archive_original_replaced')
                    os.fchown(writer.fileno(),-1,21005);os.fchmod(writer.fileno(),0o640)
                    for block in iter(lambda:reader.read(1048576),b''):
                        budget();size+=len(block)
                        if size>before.st_size:raise ValueError('operation_archive_original_grew')
                        writer.write(block);checksum.update(block)
                    after=os.fstat(reader.fileno());writer.flush();os.fsync(writer.fileno())
                if size!=before.st_size or (before.st_mtime_ns,before.st_ctime_ns)!=(after.st_mtime_ns,after.st_ctime_ns):raise ValueError('operation_archive_original_changed')
                used+=size;files.append({'name':name,'original_path':relative,'original_uid':source['uid'],
                                        'bytes':size,'digest':'sha256:'+checksum.hexdigest()})
            after_directory=parent.stat()
            if (before_directory.st_mtime_ns,before_directory.st_ctime_ns)!=(after_directory.st_mtime_ns,after_directory.st_ctime_ns):raise ValueError('operation_archive_original_directory_changed')
    value={'kind':'ControllerOperationHistorySnapshot','producer_uid':21001,'reader_gid':21005,
        'campaign':policy['campaign'],'deployment_epoch':policy['deployment_epoch'],'config_digest':policy['config_digest'],
        'policy_digest':policy['digest'],'database':database_pin,'files':files,'lock_metadata':locks,
        'spending_state':ledger.read(),'deadline':policy['deadline'],'all_attempts_successful':False,
        'physical_capacity_verified':False,'deletion_authorized':False}
    from skillloop.protocol import canonical_json_line
    if len(canonical_json_line(value))>1048576:raise ValueError('operation_archive_original_metadata_capacity')
    value['digest']=digest_jcs(value);_publish(root/'snapshot.json',value,21005)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    _save(journal,'completion.json',{'kind':'ControllerOperationArchiveCompletion','snapshot_digest':value['digest']})
    return value
