"""Admin-only archive private key custody; Gate receives no persistent key file.

The private service unwraps only a per-bundle AES key. It never mounts, reads,
or logs any private evidence or plaintext archive content.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import socket
import signal
import threading
import stat
import struct

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import canonical_json_line,decode_json,digest_bytes,digest_jcs
from skillloop.runtime.archive_crypto import locked_crypto,header_bytes,key_label


def _secret(path,limit):
    path=Path(path)
    if path.is_symlink() or path.parent.is_symlink():raise PermissionError('archive_key_symlink')
    _directory(path.parent,21010,21010,0o700)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21010 or info.st_gid!=21010
                or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit):
            raise PermissionError('archive_key_actual_admin_custody')
        return stream.read(limit+1)


class ArchiveKeyService:
    def __init__(self,policy_path):
        if os.geteuid()!=21010:raise PermissionError('archive_key_actual_admin')
        self.stop=threading.Event()
        self.policy=read_owned(policy_path,uid=21010,gid=21010,limit=262144)
        p=self.policy
        if (set(p)!={'kind','campaign','deployment_epoch','deadline','dependency_lock_path',
                'dependency_lock_digest','key_directory','public_directory','socket_directory','ready_directory','digest'}
                or p['kind']!='FrozenArchiveKeyServiceDeployment'):
            raise ValueError('archive_key_frozen_deployment')
        lock=read_owned(p['dependency_lock_path'],uid=21010,gid=21010,limit=2097152)
        if lock['digest']!=p['dependency_lock_digest']:raise ValueError('archive_key_dependency_binding')
        if p['digest']!=os.environ.get('SKILLLOOP_ARCHIVE_POLICY_DIGEST'):
            raise ValueError('archive_key_original_dispatch_policy')
        self.crypto=locked_crypto(lock)
        self.deadline=datetime.fromisoformat(p['deadline'].replace('Z','+00:00'))
        if self.deadline.tzinfo is None or datetime.now(timezone.utc)>=self.deadline:
            raise TimeoutError('archive_key_original_deadline')
        self.root=_directory(p['key_directory'],21010,21010,0o700)
        public=_directory(p['public_directory'],21010,21005,0o750)
        self.socket_root=_directory(p['socket_directory'],21010,21005,0o750)
        hashes,serialization,padding,rsa,*_=self.crypto
        path=self.root/'archive-private.pem';public_path=public/'archive-public.json'
        if path.exists():
            key=serialization.load_pem_private_key(_secret(path,8192),password=None)
        else:
            # Never rotate a key after an interrupted startup or overwrite an
            # original public key. The uncompleted operation remains recoverable.
            if any(self.root.iterdir()) or public_path.exists():raise RuntimeError('archive_original_key_recovery_required')
            key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
            raw=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        if not isinstance(key,rsa.RSAPrivateKey) or key.key_size!=3072 or key.public_key().public_numbers().e!=65537:
            raise ValueError('archive_RSA3072_admin_key')
        self.key=key
        pem=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.key_id=digest_bytes(pem)
        value={'kind':'AdminArchivePublicKey','key_id':self.key_id,'pem':pem.decode('ascii'),
            'algorithm':'RSA3072-OAEP-SHA256','dependency_lock_digest':lock['digest']}
        value['digest']=digest_jcs(value)
        if public_path.exists():
            if read_owned(public_path,uid=21010,gid=21005,limit=16384)!=value:
                raise ValueError('archive_original_public_key_changed')
        else:_publish(public_path,value,21005)

    def unwrap(self,uid,request):
        if uid!=21005:raise PermissionError('archive_key_gate_only_peer')
        if (type(request) is not dict or set(request)!={'kind','header'}
                or request['kind']!='InternalArchiveKeyUnwrap'):
            raise ValueError('archive_key_request_shape')
        h=request['header'];header_bytes(h)
        if (h['campaign']!=self.policy['campaign'] or h['deployment_epoch']!=self.policy['deployment_epoch']
                or h['key_id']!=self.key_id or h['dependency_lock_digest']!=self.policy['dependency_lock_digest']
                or datetime.now(timezone.utc)>=self.deadline):
            raise PermissionError('archive_key_original_scope')
        hashes,_,padding,*_=self.crypto
        key=self.key.decrypt(bytes.fromhex(h['wrapped_key']),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),label=key_label(h)))
        if len(key)!=32:raise ValueError('archive_key_AES256_only')
        # This ephemeral response is never journaled or written to stdout.
        return {'ok':True,'key_hex':key.hex(),'error_code':None}

    def serve(self):
        path=self.socket_root/'keys.sock'
        if os.path.lexists(path):raise RuntimeError('archive_key_original_socket_recovery_required')
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
            server.bind(str(path));os.chown(path,-1,21005);os.chmod(path,0o660)
            inode=path.lstat();server.listen(8);server.settimeout(0.5)
            ready=_directory(self.policy['ready_directory'],21010,21001,0o750)
            value={'kind':'OpaqueArchiveKeyServiceReady','policy_digest':self.policy['digest'],
                'campaign':self.policy['campaign'],'deployment_epoch':self.policy['deployment_epoch'],
                'key_id':self.key_id,'private_key_disclosed':False}
            value['digest']=digest_jcs(value);_publish(ready/'ready.json',value,21001)
            try:
                while not self.stop.is_set() and datetime.now(timezone.utc)<self.deadline:
                    try:connection,_=server.accept()
                    except socket.timeout:continue
                    with connection:
                        connection.settimeout(5)
                        try:
                            uid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                            raw,_,flags,_=connection.recvmsg(65537)
                            if not raw or len(raw)>65536 or flags&socket.MSG_TRUNC:raise ValueError('archive_key_message_bound')
                            reply=self.unwrap(uid,decode_json(raw))
                        except Exception:reply={'ok':False,'key_hex':None,'error_code':'archive_key_unavailable'}
                        try:connection.sendall(canonical_json_line(reply))
                        except OSError:pass
            finally:
                current=path.lstat()
                if (current.st_dev,current.st_ino)!=(inode.st_dev,inode.st_ino):
                    raise RuntimeError('archive_key_socket_changed')
                path.unlink()


def unwrap_for_gate(header,socket_path):
    if os.geteuid()!=21005:raise PermissionError('archive_unwrap_actual_gate')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(5);connection.connect(str(socket_path))
        if struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]!=21010:
            raise PermissionError('archive_unwrap_actual_admin_peer')
        connection.sendall(canonical_json_line({'kind':'InternalArchiveKeyUnwrap','header':header}))
        raw,_,flags,_=connection.recvmsg(4097)
    if not raw or len(raw)>4096 or flags&socket.MSG_TRUNC:raise ValueError('archive_key_response_bound')
    result=decode_json(raw)
    if type(result) is not dict or set(result)!={'ok','key_hex','error_code'} or result['ok'] is not True or result['error_code'] is not None:
        raise PermissionError('archive_key_unwrap_unavailable')
    key=bytes.fromhex(result['key_hex'])
    if len(key)!=32:raise ValueError('archive_key_response_AES256')
    return key


def main():
    os.umask(0o077)
    previous={}
    try:
        service=ArchiveKeyService('/archive-policy/key-service.json')
        for number in (signal.SIGTERM,signal.SIGINT):
            previous[number]=signal.getsignal(number)
            signal.signal(number,lambda signum,frame: service.stop.set())
        service.serve()
    except BaseException as error:
        import traceback
        try:
            root=_directory('/archive-keys',21010,21010,0o700)
            failure={'kind':'PrivateArchiveKeyServiceFailure','error_type':type(error).__name__,
                'traceback':traceback.format_exc(),'automatic_key_rotation_allowed':False}
            failure['digest']=digest_jcs(failure);_publish(root/'service.failure.json',failure,21010)
        except BaseException:pass
        raise SystemExit(1) from None
    finally:
        for number,handler in previous.items():signal.signal(number,handler)


if __name__=='__main__':main()
