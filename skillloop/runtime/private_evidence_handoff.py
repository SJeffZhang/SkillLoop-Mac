"""Copy one stopped Runtime's bytes into an Evaluator-readable current leaf.

This process has Runtime's UID, no model/Proxy socket, and a read-only source.
It neither executes the victim nor evaluates output. Partial exports remain.
"""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import time

from scripts.mac_agent_runtime import read_current_request
from skillloop.protocol import canonical_json_line, digest_jcs
from skillloop.runtime.archive_files import allocate_output, require_unchanged


def handoff():
    if os.geteuid()!=21002 or 21004 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('private_handoff_runtime_custody')
    maximum=int(os.environ['SKILLLOOP_HANDOFF_BYTES']);count=int(os.environ['SKILLLOOP_HANDOFF_FILES'])
    seconds=int(os.environ['SKILLLOOP_HANDOFF_SECONDS'])
    deadline=datetime.fromisoformat(os.environ['SKILLLOOP_HANDOFF_DEADLINE'].replace('Z','+00:00'))
    if not 1<=maximum<=20971520 or not 1<=count<=4096 or not 1<=seconds<=60 or deadline.tzinfo is None:
        raise ValueError('private_handoff_frozen_bounds')
    started=time.monotonic()
    def budget():
        if time.monotonic()-started>=seconds or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
            raise TimeoutError('private_handoff_original_clock')
    packet=read_current_request()
    if packet.get('kind')!='FormalPrivateCurrentRuntimeRequest' or packet['request']['digest']!=os.environ['SKILLLOOP_HANDOFF_REQUEST']:
        raise ValueError('private_handoff_current_request')
    source=Path('/source-evidence');output=Path('/handoff')
    info=source.lstat();target=output.lstat()
    if (source.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=21002 or info.st_mode&0o077
            or output.is_symlink() or not stat.S_ISDIR(target.st_mode)
            or (target.st_uid,target.st_gid,stat.S_IMODE(target.st_mode))!=(21002,21004,0o750)
            or any(output.iterdir())):
        raise PermissionError('private_handoff_current_directories')
    paths=[];pending=[source];total=0;enumerated=0
    while pending:
        budget();parent=pending.pop()
        with os.scandir(parent) as children:
            for child in children:
                budget();enumerated+=1
                if enumerated>count:raise ValueError('private_handoff_file_capacity')
                meta=child.stat(follow_symlinks=False);path=Path(child.path)
                if (meta.st_uid!=21002 or meta.st_mode&0o077
                        or not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode))
                        or (stat.S_ISREG(meta.st_mode) and meta.st_nlink!=1)):
                    raise PermissionError('private_handoff_source_custody')
                if stat.S_ISDIR(meta.st_mode):pending.append(path)
                else:
                    total+=meta.st_size;paths.append((path,meta))
                    if total>maximum:raise ValueError('private_handoff_byte_capacity')
    raw=canonical_json_line(packet)
    if total+len(raw)+262144>maximum or enumerated+2>count:
        raise ValueError('private_handoff_packet_and_receipt_capacity')
    space=os.statvfs(output)
    if space.f_bavail*space.f_frsize<2147483648+total+len(raw)+262144+(enumerated+2)*4096:
        raise OSError('private_handoff_complete_copy_peak_and_floor')
    inventory={}
    pin=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    for path,meta in sorted(paths,key=lambda row:str(row[0])):
        budget();relative='evidence/'+path.relative_to(source).as_posix();destination=output/relative
        missing=[];parent=destination.parent
        while parent!=output and not parent.exists():missing.append(parent);parent=parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700);os.chown(directory,-1,21004);os.chmod(directory,0o750)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as reader:
            if pin(os.fstat(reader.fileno()))!=pin(meta):raise ValueError('private_handoff_source_changed')
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            checksum=hashlib.sha256();copied=0
            with os.fdopen(fd,'wb') as writer:
                budget();allocate_output(writer.fileno(),meta.st_size);budget()
                for block in iter(lambda:reader.read(1048576),b''):
                    budget();copied+=len(block)
                    if copied>meta.st_size:raise ValueError('private_handoff_source_grew')
                    checksum.update(block);writer.write(block)
                os.fchown(writer.fileno(),-1,21004);os.fchmod(writer.fileno(),0o640)
                writer.flush();os.fsync(writer.fileno())
            if copied!=meta.st_size or pin(os.fstat(reader.fileno()))!=pin(meta):
                raise ValueError('private_handoff_source_changed_during_copy')
            require_unchanged(path,meta,os.fstat(reader.fileno()))
        check=hashlib.sha256()
        with destination.open('rb') as stream:
            for block in iter(lambda:stream.read(1048576),b''):budget();check.update(block)
        if check.digest()!=checksum.digest():raise ValueError('private_handoff_copy_digest')
        inventory[relative]={'bytes':copied,'digest':'sha256:'+checksum.hexdigest()}
    def publish(name,value):
        encoded=canonical_json_line(value)
        budget()
        fd=os.open(output/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            allocate_output(stream.fileno(),len(encoded));budget()
            os.fchown(stream.fileno(),-1,21004);os.fchmod(stream.fileno(),0o640)
            stream.write(encoded);stream.flush();os.fsync(stream.fileno())
    publish('current-request.json',packet)
    inventory['current-request.json']={'bytes':len(raw),'digest':'sha256:'+hashlib.sha256(raw).hexdigest()}
    receipt={'kind':'RuntimePrivateEvidenceHandoff','packet_digest':packet['digest'],
        'run_request_digest':packet['request']['digest'],'task_binding_digest':packet['binding']['digest'],
        'run_id':packet['binding']['body']['run_id'],'deployment_epoch':packet['deployment'],
        'files':inventory,'total_bytes':total+len(raw),'producer_uid':21002,'reader_gid':21004,
        'maximum_bytes':maximum,'maximum_files':count,'complete':True,'victim_reexecuted':False}
    receipt['digest']=digest_jcs(receipt);publish('handoff.json',receipt)
    for parent,_,_ in os.walk(output,topdown=False):
        budget();fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    return receipt


if __name__=='__main__':
    os.umask(0o077)
    handoff()
