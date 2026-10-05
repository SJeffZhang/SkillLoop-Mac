"""Controller exports its actual Registry after committed archive withdrawal."""
from contextlib import closing
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import decode_json,digest_jcs


def preserve_registry(registry,*,withdrawal,output_directory,maximum_bytes,timeout_seconds,deadline):
    if (os.geteuid()!=21001 or type(maximum_bytes) is not int or not 1048576<=maximum_bytes<=268435456
            or type(timeout_seconds) is not int or not 1<=timeout_seconds<=120
            or withdrawal.get('kind')!='RegistryArchiveWithdrawal'
            or withdrawal.get('digest')!=digest_jcs({k:v for k,v in withdrawal.items() if k!='digest'})):
        raise PermissionError('registry_archive_original_controller_and_cost')
    root=_directory(output_directory,21001,21005,0o750)
    if any(root.iterdir()):raise FileExistsError('registry_archive_original_recovery_required')
    expiry=datetime.fromisoformat(deadline.replace('Z','+00:00'));started=time.monotonic()
    target=root/'registry.sqlite'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    def bounded(*_):
        if datetime.now(timezone.utc)>=expiry or time.monotonic()-started>=timeout_seconds:
            raise TimeoutError('registry_archive_original_clock')
        if target.stat().st_size+1048576>maximum_bytes:raise ValueError('registry_archive_capacity')
    with closing(sqlite3.connect(target,timeout=2)) as db:
        db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
        with closing(sqlite3.connect(registry.path.as_uri()+'?mode=ro',uri=True,timeout=2)) as source:
            source.backup(db,pages=64,progress=bounded,sleep=0.01)
        db.set_progress_handler(lambda:int(time.monotonic()-started>=timeout_seconds),1000)
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('registry_archive_integrity')
        rows=db.execute("SELECT result FROM promotions WHERE operation LIKE 'archive-withdraw-%'").fetchall()
        if not any(decode_json(row[0])==withdrawal for row in rows):raise ValueError('registry_archive_committed_withdrawal_missing')
        campaign=withdrawal['campaign']
        original=db.execute('SELECT bindings FROM formal_campaigns WHERE campaign=?',(campaign,)).fetchone()
        if original is None:raise ValueError('registry_archive_registered_campaign_missing')
        bindings=decode_json(original[0])
        try:registry._archive_fence(db,campaign)
        except ValueError as error:
            if str(error)!='campaign_closed_by_archive_withdrawal':raise
        else:raise ValueError('registry_archive_actual_fence_missing')
    bounded();checksum=hashlib.sha256()
    with target.open('r+b') as stream:
        for block in iter(lambda:stream.read(1048576),b''):bounded();checksum.update(block)
        os.fchown(stream.fileno(),-1,21005);os.fchmod(stream.fileno(),0o640);os.fsync(stream.fileno())
    value={'kind':'ControllerWithdrawnRegistrySnapshot','producer_uid':21001,'reader_gid':21005,
        'campaign':campaign,'bindings':bindings,'withdrawal':withdrawal,'database_digest':'sha256:'+checksum.hexdigest(),
        'database_size_bytes':target.stat().st_size,'database_name':'registry.sqlite',
        'deadline':deadline,'maximum_bytes':maximum_bytes,'campaign_dispatch_closed':True,'deletion_authorized':False}
    value['digest']=digest_jcs(value);_publish(root/'snapshot.json',value,21005)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return value


def dispatch_registry_snapshot(*,registry,policy_path,journal_directory,ledger,whole_round_manifest_path):
    from skillloop.runtime.round_manifest import read_round_manifest
    from skillloop.runtime.proposal_dispatch import _save
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=262144)
    fields={'kind','campaign','deployment_epoch','config_digest','withdrawal_operation_id',
            'output_directory','maximum_bytes','timeout_seconds','deadline','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenRegistryArchiveSnapshot'
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=120
            or type(policy['maximum_bytes']) is not int or not 1048576<=policy['maximum_bytes']<=268435456):
        raise ValueError('registry_snapshot_frozen_policy')
    whole=read_round_manifest(whole_round_manifest_path)
    if whole['deployment_epoch']!=policy['deployment_epoch'] or not any(c['campaign_digest']==policy['campaign'] for c in whole['campaigns']):
        raise ValueError('registry_snapshot_original_round')
    journal=_directory(journal_directory,21001,21001,0o700)
    if any(journal.iterdir()):raise RuntimeError('registry_snapshot_original_operation_recovery_required')
    with closing(sqlite3.connect(registry.path,timeout=2)) as db:
        row=db.execute('SELECT result FROM promotions WHERE operation=?',('archive-withdraw-'+policy['withdrawal_operation_id'],)).fetchone()
        clock=db.execute('SELECT deadline FROM campaign_original_clocks WHERE campaign=?',(policy['campaign'],)).fetchone()
    if row is None or clock!=(policy['deadline'],):raise ValueError('registry_snapshot_committed_original_withdrawal_and_clock')
    withdrawal=decode_json(row[0])
    if withdrawal['campaign']!=policy['campaign']:raise ValueError('registry_snapshot_withdrawal_campaign')
    expiry=datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'))
    if (ledger.campaign_started_at is None or expiry.timestamp()!=ledger.campaign_started_at+28800
            or (expiry-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+60):
        raise TimeoutError('registry_snapshot_original_budget_clock')
    cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign'],stage='resource_archive_restore',
        operation_key='registry-snapshot-'+policy['digest'][7:],seconds=policy['timeout_seconds']+60,
        input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_bytes'])
    _save(journal,'intent.json',{'kind':'RegistryArchiveSnapshotIntent','policy_digest':policy['digest'],'spending':cost})
    result=preserve_registry(registry,withdrawal=withdrawal,output_directory=policy['output_directory'],
        maximum_bytes=policy['maximum_bytes'],timeout_seconds=policy['timeout_seconds'],deadline=policy['deadline'])
    if result['bindings']['config_digest']!=policy['config_digest'] or result['bindings']['deployment_epoch']!=policy['deployment_epoch']:
        raise ValueError('registry_snapshot_original_configuration')
    _save(journal,'completion.json',{'kind':'RegistryArchiveSnapshotCompletion','snapshot_digest':result['digest']})
    return result
