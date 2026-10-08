"""Authenticate a complete archive into a fresh, inert Gate evidence vault.

Restored history is never mounted as an operational database. New deployment
bootstrap must issue new credentials; old approvals and qualification remain
historical bytes, with no automatic trust import.
"""
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path,PurePosixPath
import stat
import struct
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs
from skillloop.runtime.archive_crypto import locked_crypto,read_header,verify_stream
from skillloop.runtime.archive_files import allocate_output,open_original
from skillloop.runtime.archive_key_service import unwrap_for_gate
from skillloop.runtime.encrypted_archive import _hash


class _PlainReader:
    def __init__(self,source,key,crypto,header,budget):
        _,_,_,_,Cipher,algorithms,modes=crypto
        observed,aad=read_header(source)
        if observed!=header:raise ValueError('restore_original_header_changed')
        start=source.tell();source.seek(0,2);end=source.tell()
        if end-start<16:raise ValueError('restore_missing_tag')
        source.seek(end-16);tag=source.read(16);source.seek(start)
        self.remaining=end-start-16;self.source=source;self.budget=budget
        self.decryptor=Cipher(algorithms.AES256(key),modes.GCM(bytes.fromhex(header['nonce']),tag)).decryptor()
        self.decryptor.authenticate_additional_data(aad);self.buffer=b'';self.finished=False
    def read(self,count):
        while len(self.buffer)<count and not self.finished:
            self.budget()
            if self.remaining:
                block=self.source.read(min(1048576,self.remaining))
                if not block:raise ValueError('restore_truncated_cipher')
                self.remaining-=len(block);self.buffer+=self.decryptor.update(block)
            else:self.buffer+=self.decryptor.finalize();self.finished=True
        result=self.buffer[:count];self.buffer=self.buffer[count:]
        if len(result)!=count:raise ValueError('restore_truncated_plaintext')
        return result
    def finish(self):
        if self.buffer or self.remaining:raise ValueError('restore_extra_plaintext')
        if not self.finished:
            if self.decryptor.finalize():raise ValueError('restore_extra_final_plaintext')
            self.finished=True


def run_restore(policy_path):
    if os.geteuid()!=21005:raise PermissionError('restore_actual_gate_required')
    policy=read_owned(policy_path,uid=21010,gid=21005,limit=2097152)
    fields={'kind','campaign','deployment_epoch','new_deployment_epoch','operation_ref','bundle_path',
        'export_receipt_path','review_path','dependency_lock_path','dependency_lock_digest','key_socket',
        'restored_directory','private_directory','public_directory','maximum_bytes','maximum_files',
        'timeout_seconds','deadline','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenEncryptedEvidenceRestoreDeployment'
            or policy['digest']!=os.environ.get('SKILLLOOP_ARCHIVE_POLICY_DIGEST')
            or type(policy['new_deployment_epoch']) is not str or not 1<=len(policy['new_deployment_epoch'])<=256
            or policy['new_deployment_epoch']==policy['deployment_epoch']
            or type(policy['maximum_bytes']) is not int or not 1<=policy['maximum_bytes']<=2147483648
            or type(policy['maximum_files']) is not int or not 1<=policy['maximum_files']<=4096
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=1200):
        raise ValueError('restore_frozen_new_epoch_policy')
    started=time.monotonic();deadline=datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'))
    def budget():
        if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline or time.monotonic()-started>=policy['timeout_seconds']:
            raise TimeoutError('restore_original_budget_clock')
    budget();lock=read_owned(policy['dependency_lock_path'],uid=21010,gid=21005,limit=2097152)
    if lock['digest']!=policy['dependency_lock_digest']:raise ValueError('restore_original_crypto_lock')
    crypto=locked_crypto(lock)
    receipt=read_owned(policy['export_receipt_path'],uid=21005,gid=21005,limit=16777216)
    review=read_owned(policy['review_path'],uid=21005,gid=21005,limit=262144)
    if (review.get('kind')!='IndependentEncryptedEvidenceReview'
            or receipt.get('kind')!='EncryptedEvidenceExportReceipt'
            or review.get('export_receipt_digest')!=receipt['digest']
            or review.get('encrypted_bundle_digest')!=receipt['encrypted_bundle_digest']
            or review.get('authenticated_content_verified') is not True
            or review.get('campaign_coverage_complete') is not True):
        raise ValueError('restore_complete_independent_campaign_archive_required')
    root=_directory(policy['restored_directory'],21005,21005,0o700)
    private=_directory(policy['private_directory'],21005,21005,0o750)
    public=_directory(policy['public_directory'],21005,21001,0o750)
    if any(root.iterdir()):raise RuntimeError('restore_original_partial_vault_preserved')
    cipher=Path(policy['bundle_path']);cipher_digest,before=_hash(cipher,budget)
    if (before.st_uid!=21005 or before.st_gid!=21010 or stat.S_IMODE(before.st_mode)!=0o640
            or cipher_digest!=review['encrypted_bundle_digest']):raise ValueError('restore_actual_reviewed_cipher')
    # Reopen through the entire original component chain. Checking only the
    # final component would let a changed parent redirect this second read.
    fd=open_original(cipher)
    with os.fdopen(fd,'rb') as source:
        header,_=read_header(source)
        if (header!=receipt['header'] or header['campaign']!=policy['campaign'] or header['deployment_epoch']!=policy['deployment_epoch']
                or header['dependency_lock_digest']!=lock['digest']):raise ValueError('restore_original_archive_identity')
        key=unwrap_for_gate(header,policy['key_socket']);source.seek(0)
        verify_stream(source=source,key=key,crypto=crypto,expected_header=header,budget=budget)
        # Authenticate before any plaintext is written. Authenticate the second
        # pass too; interrupted or changed ciphertext never gets a completion.
        source.seek(0);reader=_PlainReader(source,key,crypto,header,budget)
        if reader.read(len(b'SL-EVIDENCE-1\n'))!=b'SL-EVIDENCE-1\n':raise ValueError('restore_plain_format')
        count=struct.unpack('>I',reader.read(4))[0]
        if not 1<=count<=8388608:raise ValueError('restore_inventory_capacity')
        raw=reader.read(count);inventory=decode_json(raw)
        if (canonical_json_line(inventory)!=raw or inventory.get('kind')!='FrozenEncryptedEvidenceInventory'
                or inventory.get('digest')!=digest_jcs({k:v for k,v in inventory.items() if k!='digest'})
                or inventory['digest']!=header['source_manifest_digest']
                or inventory['campaign']!=policy['campaign'] or inventory['deployment_epoch']!=policy['deployment_epoch']
                or type(inventory.get('allocated_source_bytes')) is not int
                or not 0<=inventory['allocated_source_bytes']+1048576<=2147483648
                or type(inventory['files']) is not list or not 1<=len(inventory['files'])<=policy['maximum_files']):
            raise ValueError('restore_original_complete_inventory')
        total=0;seen=set();files=[]
        for row in inventory['files']:
            budget();name=PurePosixPath(row['path'])
            if (set(row)!={'path','bytes','digest','uid','gid','mode'} or name.is_absolute()
                    or str(name)!=row['path'] or len(name.parts)<2 or '..' in name.parts
                    or '\\' in row['path'] or '\x00' in row['path'] or row['path'].casefold() in seen
                    or type(row['bytes']) is not int or row['bytes']<0):raise ValueError('restore_safe_inventory_path')
            seen.add(row['path'].casefold());total+=row['bytes']
            if total>policy['maximum_bytes'] or total+1048576>int(os.environ['SKILLLOOP_ARCHIVE_MAX_BYTES']):
                raise ValueError('restore_original_capacity')
            space=os.statvfs(root)
            if space.f_bavail*space.f_frsize<row['bytes']+2147483648:raise OSError('restore_actual_free_floor')
            target=root/str(name);target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
            for parent in (target.parent,*target.parent.parents):
                if parent==root.parent:break
                if parent.is_symlink() or parent.stat().st_uid!=21005:raise PermissionError('restore_private_parent_custody')
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            checksum=hashlib.sha256();remaining=row['bytes']
            with os.fdopen(fd,'wb') as stream:
                budget();allocate_output(stream.fileno(),remaining);budget()
                while remaining:
                    budget();block=reader.read(min(1048576,remaining));remaining-=len(block)
                    stream.write(block);checksum.update(block)
                stream.flush();os.fsync(stream.fileno())
            if 'sha256:'+checksum.hexdigest()!=row['digest']:raise ValueError('restore_original_file_bytes')
            directory=target.parent
            while directory.is_relative_to(root):
                fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
                if directory==root:break
                directory=directory.parent
            files.append({'path':row['path'],'digest':row['digest'],'bytes':row['bytes']})
        reader.finish();del key
        if total!=inventory['total_bytes']:raise ValueError('restore_inventory_total')
    if _hash(cipher,budget)[0]!=cipher_digest:raise ValueError('restore_cipher_changed_during_materialization')
    result={'kind':'InertEncryptedEvidenceRestore','policy_digest':policy['digest'],'campaign':policy['campaign'],
        'old_deployment_epoch':policy['deployment_epoch'],'new_deployment_epoch':policy['new_deployment_epoch'],
        'encrypted_bundle_digest':cipher_digest,'source_inventory_digest':inventory['digest'],'files':files,
        'old_credentials_activated':False,'qualification_restored':False,'operational_database_imported':False,
        'fresh_admin_admission_required':True,'deletion_authorized':False}
    result['digest']=digest_jcs(result);_publish(private/'restore.json',result,21005)
    completion={'kind':'OpaqueEncryptedEvidenceRestoreCompletion','policy_digest':policy['digest'],
        'encrypted_bundle_digest':cipher_digest,'restored_receipt_digest':result['digest'],
        'new_deployment_epoch':policy['new_deployment_epoch'],'old_credentials_activated':False,
        'campaign_coverage_complete':True,'deletion_authorized':False}
    completion['digest']=digest_jcs(completion);_publish(public/'restore.json',completion,21001)
    return completion


def main():
    os.umask(0o077)
    try:run_restore('/archive-policy/restore.json')
    except BaseException:
        import traceback
        try:
            root=_directory('/private-result',21005,21005,0o750)
            failure={'kind':'PrivateEncryptedRestoreFailure','traceback':traceback.format_exc(),
                     'automatic_reexecution_allowed':False}
            failure['digest']=digest_jcs(failure);_publish(root/'restore.failure.json',failure,21005)
        except BaseException:pass
        raise SystemExit(1) from None


if __name__=='__main__':main()
