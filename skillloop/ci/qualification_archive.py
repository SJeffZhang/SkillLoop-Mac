"""Gate preserves real post-withdrawal issuer stores under original costs."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import time

from skillloop.protocol import decode_json, digest_jcs
from skillloop.protection.current_task import _directory, _publish


def preserve_withdrawn_issuer(issuer, receipt, *, assignment_digest, deadline,
                              maximum_bytes, timeout_seconds):
    if (os.geteuid()!=21005 or type(maximum_bytes) is not int
            or not 1048576<=maximum_bytes<=268435456
            or type(timeout_seconds) is not int or not 1<=timeout_seconds<=120):
        raise PermissionError('qualification_archive_original_gate_budget')
    expiry=datetime.fromisoformat(deadline.replace('Z','+00:00'))
    root=_directory(issuer.private_path.parent,21005,21005,0o700)
    prefix='withdrawn-'+assignment_digest[7:]
    started=time.monotonic();used=0;files=[]
    def bounded():
        if time.monotonic()-started>=timeout_seconds or datetime.now(timezone.utc)>=expiry:
            raise TimeoutError('qualification_archive_original_clock')
    for name,source_path,version in (('eligibility',issuer.path,2),('proofs',issuer.private_path,3)):
        bounded();target=root/(prefix+'-'+name+'.sqlite')
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.close(fd)
        with closing(sqlite3.connect(target,timeout=2)) as destination:
            destination.execute('PRAGMA journal_mode=DELETE')
            destination.execute('PRAGMA synchronous=FULL')
            def progress(*_):
                bounded()
                if target.stat().st_size+used+1048576>maximum_bytes:
                    raise ValueError('qualification_archive_original_capacity')
            with closing(sqlite3.connect(Path(source_path).as_uri()+'?mode=ro',uri=True,timeout=2)) as source:
                source.backup(destination,pages=64,progress=progress,sleep=0.01)
            destination.set_progress_handler(lambda:int(time.monotonic()-started>=timeout_seconds),1000)
            if (destination.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]
                    or destination.execute('PRAGMA user_version').fetchone()!=(version,)):
                raise ValueError('qualification_archive_consistent_store_required')
            identity_table='qualification_identity' if name=='eligibility' else 'private_qualification_identity'
            if destination.execute('SELECT epoch,config FROM '+identity_table+' WHERE singleton=1').fetchone()!=(issuer.epoch,issuer.config):
                raise ValueError('qualification_archive_original_store_identity')
            campaign=receipt['bindings']['campaign']
            if name=='eligibility':
                row=destination.execute('SELECT proof,revoked FROM issued_campaigns WHERE campaign=?',(campaign,)).fetchone()
                if row is None or row[1]!=1 or decode_json(row[0]).get('digest')!=receipt['eligibility_digest']:
                    raise ValueError('qualification_archive_actual_revocation_missing')
            else:
                row=destination.execute('SELECT bindings_digest,proof FROM private_campaign_proofs WHERE campaign=?',(campaign,)).fetchone()
                if row is None or row[0]!=digest_jcs(receipt['bindings']):
                    raise ValueError('qualification_archive_original_private_proof_missing')
        bounded();size=target.stat().st_size;checksum=hashlib.sha256()
        with target.open('r+b') as stream:
            for block in iter(lambda:stream.read(1048576),b''):
                bounded();checksum.update(block)
            os.fsync(stream.fileno())
        used+=size
        if used+1048576>maximum_bytes:raise ValueError('qualification_archive_original_capacity')
        files.append({'name':target.name,'bytes':size,'digest':'sha256:'+checksum.hexdigest(),'user_version':version})
    value={'kind':'GateWithdrawnQualificationSnapshot','producer_uid':21005,'reader_gid':21005,
        'campaign':receipt['bindings']['campaign'],'deployment_epoch':issuer.epoch,'config_digest':issuer.config,
        'assignment_digest':assignment_digest,'withdrawal_digest':receipt['digest'],
        'bindings':receipt['bindings'],'files':files,'maximum_bytes':maximum_bytes,
        'deadline':deadline,'qualification_revoked':True,'deletion_authorized':False}
    value['digest']=digest_jcs(value)
    _publish(root/(prefix+'.snapshot.json'),value,21005)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return value
