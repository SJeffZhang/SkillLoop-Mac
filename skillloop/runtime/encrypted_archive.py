"""Gate-owned encrypted evidence export and independent content review.

No plaintext temporary archive is created. This preserves the selected frozen
inventory; full campaign coverage and permission to delete originals are
separate mandatory reviews, never inferred from successful encryption.
"""
from datetime import datetime,timezone
import hashlib
import os
from pathlib import Path,PurePosixPath
import re
import stat
import struct
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import canonical_json_line,decode_json,digest_bytes,digest_jcs
from skillloop.runtime.archive_crypto import locked_crypto,key_label,encrypt_stream,verify_stream,read_header,header_bytes,MAGIC
from skillloop.runtime.archive_key_service import unwrap_for_gate
from skillloop.runtime.archive_files import open_original,identity,require_unchanged,allocate_output


def _hash(path,budget):
    checksum=hashlib.sha256()
    fd=open_original(path)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise ValueError('archive_source_regular_single_link')
        for block in iter(lambda:stream.read(1048576),b''):budget();checksum.update(block)
        after=os.fstat(stream.fileno())
    require_unchanged(path,before,after)
    return 'sha256:'+checksum.hexdigest(),before


def _inventory(policy,budget):
    rows=[];count=0;total=0;roots=policy['sources']
    if type(roots) is not list or not 1<=len(roots)<=32:raise ValueError('archive_declared_source_roots')
    aliases=set()
    for root in roots:
        if (type(root) is not dict or set(root)!={'alias','path','uid','gid','mode'}
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',root['alias']) or root['alias'] in aliases
                or root['uid'] not in {21001,21003,21004,21005} or root['gid']!=21005
                or root['mode'] not in {448,488}):
            raise ValueError('archive_original_private_source_custody')
        aliases.add(root['alias']);base=_directory(root['path'],root['uid'],root['gid'],root['mode'])
        if '..' in base.parts or any(p.is_symlink() for p in base.parents):raise ValueError('archive_source_parent_symlink')
        pending=[base]
        while pending:
            budget();parent=pending.pop();before_directory=parent.lstat()
            with os.scandir(parent) as children:
                for child in children:
                    count+=1
                    if count>policy['maximum_files']:raise ValueError('archive_inventory_capacity')
                    path=Path(child.path);meta=child.stat(follow_symlinks=False)
                    if (meta.st_uid!=root['uid'] or meta.st_gid!=root['gid']
                            or not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode))
                            or stat.S_IMODE(meta.st_mode) not in ({448,488} if stat.S_ISDIR(meta.st_mode) else {384,416})):
                        raise PermissionError('archive_source_descendant_custody')
                    if stat.S_ISDIR(meta.st_mode):pending.append(path);continue
                    if path.name.endswith(('-wal','-shm','-journal')):
                        raise ValueError('archive_standalone_owner_snapshot_required')
                    total+=meta.st_size
                    if total>policy['maximum_bytes']:raise ValueError('archive_original_inventory_byte_budget')
                    digest,actual=_hash(path,budget)
                    if identity(actual)!=identity(meta):
                        raise ValueError('archive_source_changed_before_inventory')
                    relative=path.relative_to(base).as_posix()
                    if len(relative)>1024 or '..' in PurePosixPath(relative).parts:raise ValueError('archive_relative_path_capacity')
                    rows.append({'path':root['alias']+'/'+relative,'bytes':meta.st_size,'digest':digest,
                        'uid':meta.st_uid,'gid':meta.st_gid,'mode':stat.S_IMODE(meta.st_mode)})
            if identity(parent.lstat())!=identity(before_directory):
                raise ValueError('archive_source_directory_changed')
    rows.sort(key=lambda r:r['path'])
    if not rows or len({r['path'] for r in rows})!=len(rows):raise ValueError('archive_nonempty_unique_inventory')
    value={'kind':'FrozenEncryptedEvidenceInventory','campaign':policy['campaign'],
        'deployment_epoch':policy['deployment_epoch'],'files':rows,'total_bytes':total}
    value['digest']=digest_jcs(value)
    if len(canonical_json_line(value))>8388608:raise ValueError('archive_inventory_manifest_capacity')
    return value


def _chunks(inventory,policy,budget):
    raw=canonical_json_line(inventory)
    yield b'SL-EVIDENCE-1\n'+struct.pack('>I',len(raw))+raw
    roots={r['alias']:Path(r['path']) for r in policy['sources']}
    for row in inventory['files']:
        alias,relative=row['path'].split('/',1);path=roots[alias]/relative
        fd=open_original(path)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());checksum=hashlib.sha256();size=0
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode),before.st_size)
                        !=(row['uid'],row['gid'],row['mode'],row['bytes'])):
                raise ValueError('archive_original_source_changed_before_encrypt')
            for block in iter(lambda:stream.read(1048576),b''):
                budget();size+=len(block)
                if size>row['bytes']:raise ValueError('archive_source_grew')
                checksum.update(block);yield block
            after=os.fstat(stream.fileno())
        require_unchanged(path,before,after)
        if size!=row['bytes'] or 'sha256:'+checksum.hexdigest()!=row['digest']:
            raise ValueError('archive_original_bytes_changed_during_encrypt')


def run_export(policy_path,*,review=False):
    if os.geteuid()!=21005:raise PermissionError('archive_actual_gate_export_or_review')
    policy=read_owned(policy_path,uid=21010,gid=21005,limit=2097152)
    fields={'kind','campaign','deployment_epoch','operation_ref','sources','maximum_bytes','maximum_files',
        'timeout_seconds','deadline','dependency_lock_path','dependency_lock_digest','public_key_path',
        'key_socket','encrypted_directory','private_directory','public_directory',
        'campaign_gate_evidence_path','archive_obligations_path','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenEncryptedEvidenceExportDeployment'
            or type(policy['maximum_bytes']) is not int or not 1<=policy['maximum_bytes']<=2147483648
            or type(policy['maximum_files']) is not int or not 1<=policy['maximum_files']<=4096
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=1200):
        raise ValueError('archive_full_frozen_export_budget')
    if (policy['digest']!=os.environ.get('SKILLLOOP_ARCHIVE_POLICY_DIGEST')
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',policy['campaign'])
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',policy['operation_ref'])
            or type(policy['deployment_epoch']) is not str or not 1<=len(policy['deployment_epoch'])<=256):
        raise ValueError('archive_original_dispatch_identity')
    lock=read_owned(policy['dependency_lock_path'],uid=21010,gid=21005,limit=2097152)
    if lock['digest']!=policy['dependency_lock_digest']:raise ValueError('archive_dependency_lock_binding')
    crypto=locked_crypto(lock);started=time.monotonic()
    deadline=datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'))
    def budget():
        if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline or time.monotonic()-started>=policy['timeout_seconds']:
            raise TimeoutError('archive_original_export_clock')
    budget()
    encrypted=_directory(policy['encrypted_directory'],21005,21010,0o750)
    private=_directory(policy['private_directory'],21005,21005,0o750)
    public=_directory(policy['public_directory'],21005,21001,0o750)
    if any(base==Path(r['path']) or base in Path(r['path']).parents or Path(r['path']) in base.parents
            for base in (encrypted,private,public) for r in policy['sources']):
        raise ValueError('archive_source_output_roots_must_be_disjoint')
    inventory=_inventory(policy,budget);maximum_output=int(os.environ['SKILLLOOP_ARCHIVE_MAX_BYTES'])
    if not 1<=maximum_output<=2147483648:raise ValueError('archive_original_output_slot_capacity')
    bundle=encrypted/(policy['operation_ref']+'.bundle')
    receipt_path=private/(policy['operation_ref']+'.export.json')
    if review:
        receipt=read_owned(receipt_path,uid=21005,gid=21005,limit=262144)
        if (receipt.get('kind')!='EncryptedEvidenceExportReceipt' or receipt['policy_digest']!=policy['digest']
                or receipt['source_manifest_digest']!=inventory['digest']):raise ValueError('archive_review_original_receipt')
        cipher_digest,meta=_hash(bundle,budget)
        if (meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))!=(21005,21010,0o640) or meta.st_size>maximum_output:
            raise ValueError('archive_review_ciphertext_custody_capacity')
        if cipher_digest!=receipt['encrypted_bundle_digest']:raise ValueError('archive_review_ciphertext_changed')
        with bundle.open('rb') as stream:header,_=read_header(stream)
        if header!=receipt['header']:raise ValueError('archive_review_original_header')
        key=unwrap_for_gate(header,policy['key_socket'])
        checksum=hashlib.sha256();size=0
        for block in _chunks(inventory,policy,budget):checksum.update(block);size+=len(block)
        with bundle.open('rb') as stream:actual=verify_stream(source=stream,key=key,crypto=crypto,expected_header=header,budget=budget)
        del key
        if actual!=('sha256:'+checksum.hexdigest(),size):raise ValueError('archive_review_authenticated_original_content')
        if _inventory(policy,budget)!=inventory:raise ValueError('archive_review_inventory_changed')
        from skillloop.runtime.campaign_archive_coverage import review_campaign_inventory
        coverage=review_campaign_inventory(policy=policy,inventory=inventory,budget=budget)
        if _inventory(policy,budget)!=inventory:raise ValueError('archive_campaign_coverage_inventory_changed')
        _publish(private/(policy['operation_ref']+'.coverage.json'),coverage,21005)
        result={'kind':'IndependentEncryptedEvidenceReview','policy_digest':policy['digest'],
            'export_receipt_digest':receipt['digest'],'encrypted_bundle_digest':cipher_digest,
            'authenticated_content_verified':True,'selected_inventory_complete':True,
            'campaign_coverage_review_digest':coverage['digest'],
            'all_reviewed_task_bytes_present':coverage['all_reviewed_task_bytes_present'],
            'campaign_coverage_complete':False,'qualification_withdrawn':False,'deletion_authorized':False}
        result['digest']=digest_jcs(result);_publish(private/(policy['operation_ref']+'.review.json'),result,21005)
        completion={'kind':'OpaqueEncryptedEvidenceReviewCompletion','policy_digest':policy['digest'],
            'campaign':policy['campaign'],'deployment_epoch':policy['deployment_epoch'],'key_id':header['key_id'],
            'encrypted_bundle_digest':cipher_digest,'selected_inventory_verified':True,
            'all_reviewed_task_bytes_present':coverage['all_reviewed_task_bytes_present'],
            'campaign_coverage_complete':False,
            'deletion_authorized':False};completion['digest']=digest_jcs(completion)
        _publish(public/(policy['operation_ref']+'.review.json'),completion,21001);return completion
    if any(os.path.lexists(p) for p in (bundle,receipt_path,private/(policy['operation_ref']+'.intent.json'))):
        raise RuntimeError('archive_original_partial_export_preserved_no_reencrypt')
    pem=read_owned(policy['public_key_path'],uid=21010,gid=21005,limit=16384)
    if (pem.get('kind')!='AdminArchivePublicKey' or pem.get('algorithm')!='RSA3072-OAEP-SHA256'
            or pem.get('dependency_lock_digest')!=lock['digest']):raise ValueError('archive_original_admin_public_key')
    hashes,serialization,padding,rsa,*_=crypto
    key=serialization.load_pem_public_key(pem['pem'].encode('ascii'))
    if not isinstance(key,rsa.RSAPublicKey) or key.key_size!=3072 or key.public_numbers().e!=65537:
        raise ValueError('archive_admin_RSA3072_public_key')
    if digest_bytes(pem['pem'].encode('ascii'))!=pem['key_id']:raise ValueError('archive_admin_key_id')
    data_key=os.urandom(32)
    header={'kind':'AES256GCMArchiveHeader','campaign':policy['campaign'],'deployment_epoch':policy['deployment_epoch'],
        'operation_ref':policy['operation_ref'],'source_manifest_digest':inventory['digest'],
        'dependency_lock_digest':lock['digest'],'key_id':pem['key_id'],'wrapped_key':'','nonce':os.urandom(12).hex()}
    header['wrapped_key']=key.encrypt(data_key,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=key_label(header))).hex()
    payload_size=len(b'SL-EVIDENCE-1\n')+4+len(canonical_json_line(inventory))+inventory['total_bytes']
    cipher_size=len(MAGIC)+4+len(header_bytes(header))+payload_size+16
    if cipher_size+1048576>maximum_output:raise ValueError('archive_full_output_slot_capacity_before_effects')
    fs=os.statvfs(encrypted)
    if fs.f_bavail*fs.f_frsize<2147483648+inventory['total_bytes']+8388608:
        raise OSError('archive_export_actual_free_floor')
    intent={'kind':'EncryptedEvidenceExportIntent','policy_digest':policy['digest'],
        'source_manifest_digest':inventory['digest'],'header':header};intent['digest']=digest_jcs(intent)
    _publish(private/(policy['operation_ref']+'.intent.json'),intent,21005)
    fd=os.open(bundle,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as output:
        os.fchown(output.fileno(),-1,21010);os.fchmod(output.fileno(),0o640)
        budget();allocate_output(output.fileno(),cipher_size);budget()
        clear_digest,clear_size=encrypt_stream(output=output,chunks=_chunks(inventory,policy,budget),header=header,key=data_key,crypto=crypto,budget=budget)
        if output.tell()!=cipher_size:raise ValueError('archive_original_ciphertext_extent_length')
        output.flush();os.fsync(output.fileno())
    with bundle.open('rb') as stream:
        if verify_stream(source=stream,key=data_key,crypto=crypto,expected_header=header,budget=budget)!=(clear_digest,clear_size):
            raise ValueError('archive_producer_authenticated_write_verification')
    del data_key
    if _inventory(policy,budget)!=inventory:raise ValueError('archive_final_inventory_changed')
    ciphertext,meta=_hash(bundle,budget)
    if meta.st_size!=cipher_size or meta.st_blocks*512<meta.st_size:raise ValueError('archive_actual_ciphertext_allocation')
    fd=os.open(encrypted,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    receipt={'kind':'EncryptedEvidenceExportReceipt','policy_digest':policy['digest'],'header':header,
        'source_manifest_digest':inventory['digest'],'encrypted_bundle_digest':ciphertext,
        'ciphertext_bytes':meta.st_size,'source_bytes':inventory['total_bytes'],
        'campaign_coverage_complete':False,'deletion_authorized':False}
    receipt['digest']=digest_jcs(receipt);_publish(receipt_path,receipt,21005)
    completion={'kind':'OpaqueEncryptedEvidenceExportCompletion','policy_digest':policy['digest'],
        'encrypted_bundle_digest':ciphertext,'encrypted_bytes':meta.st_size,'independent_review_complete':False,
        'campaign_coverage_complete':False,'deletion_authorized':False}
    completion['digest']=digest_jcs(completion);_publish(public/(policy['operation_ref']+'.export.json'),completion,21001)
    return completion


def main():
    os.umask(0o077)
    mode=os.environ.get('SKILLLOOP_ARCHIVE_ACTION')
    if mode not in {'export','review'}:raise ValueError('archive_fixed_worker_action')
    try:run_export('/archive-policy/export.json',review=mode=='review')
    except BaseException as error:
        # Detailed failures remain Gate-private. Never echo source paths,
        # inventories or a cryptography exception into a public projection.
        import traceback
        try:
            root=_directory('/private-result',21005,21005,0o750)
            failure={'kind':'PrivateEncryptedArchiveFailure','action':mode,
                'policy_digest':os.environ.get('SKILLLOOP_ARCHIVE_POLICY_DIGEST'),
                'error_type':type(error).__name__,'traceback':traceback.format_exc(),
                'automatic_reexecution_allowed':False}
            failure['digest']=digest_jcs(failure);_publish(root/(mode+'.failure.json'),failure,21005)
        except BaseException:pass  # Nonzero process exit remains the last observable evidence.
        raise SystemExit(1) from None


if __name__=='__main__':main()
