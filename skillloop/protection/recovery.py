"""Restore a trusted authority into a fresh, unqualified deployment instance."""
import os,sqlite3,tempfile,stat
from contextlib import closing
from pathlib import Path
from urllib.parse import quote
from skillloop.protocol import digest_bytes,digest_jcs


def restore_authority(source:Path,target:Path,*,new_epoch:str):
    source=Path(source).absolute();target=Path(target).absolute()
    # Do not normalize an untrusted symlink into an apparently trusted backup.
    for path in (source,target):
        if '..' in path.parts or any(parent.is_symlink() for parent in (path,*path.parents)):
            raise ValueError('restore_symlink_or_traversal')
    original_info=source.lstat()
    if not stat.S_ISREG(original_info.st_mode) or original_info.st_nlink!=1:
        raise ValueError('restore_regular_owned_backup_required')
    if target.exists() or target.is_symlink():raise FileExistsError('restore_target_exists')
    if not new_epoch or source==target:raise ValueError('restore_requires_fresh_epoch')
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    parent_info=target.parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid!=os.geteuid()
            or stat.S_IMODE(parent_info.st_mode)!=0o700):
        raise PermissionError('restore_private_target_directory')
    # Only a standalone consistent backup is a restore input. A live WAL
    # authority must first be copied by its owner through SQLite backup.
    if any(Path(str(source)+suffix).exists() for suffix in ('-wal','-shm','-journal')):
        raise ValueError('restore_standalone_consistent_backup_required')
    source_digest=digest_bytes(source.read_bytes())
    descriptor,name=tempfile.mkstemp(prefix='.restore-',suffix='.sqlite',dir=target.parent);os.close(descriptor);temporary=Path(name)
    try:
        with closing(sqlite3.connect('file:'+quote(str(source),safe='/')+'?mode=ro&immutable=1',uri=True)) as original,closing(sqlite3.connect(temporary)) as restored:
            schema_version=original.execute('PRAGMA user_version').fetchone()[0]
            if schema_version not in (1,2):raise ValueError('restore_schema_version')
            original.backup(restored)
            restored.execute('PRAGMA journal_mode=DELETE')
            if restored.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise ValueError('restore_source_integrity')
            old,revision=restored.execute('SELECT deployment_epoch,trust_revision FROM trust_state WHERE singleton=1').fetchone()
            if old==new_epoch:raise ValueError('restore_requires_fresh_epoch')
            backup_digest=digest_bytes(temporary.read_bytes())
            restored.execute('PRAGMA synchronous=FULL');restored.execute('BEGIN IMMEDIATE')
            revoked=restored.execute("UPDATE approvals SET state='revoked' WHERE state!='revoked'").rowcount
            cancelled=restored.execute("UPDATE runs SET state='cancelled',fence=fence+1").rowcount
            restored.execute('UPDATE trust_state SET deployment_epoch=?,trust_revision=? WHERE singleton=1',(new_epoch,revision+1));restored.commit()
            if restored.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise ValueError('restore_target_integrity')
        current_info=source.lstat()
        if ((current_info.st_dev,current_info.st_ino,current_info.st_size,current_info.st_mtime_ns)
                !=(original_info.st_dev,original_info.st_ino,original_info.st_size,original_info.st_mtime_ns)
                or digest_bytes(source.read_bytes())!=source_digest
                or any(Path(str(source)+suffix).exists() for suffix in ('-wal','-shm','-journal'))):
            raise ValueError('restore_source_changed')
        os.chmod(temporary,0o600)
        with temporary.open('rb') as stream:os.fsync(stream.fileno())
        os.link(temporary,target);os.chmod(target,0o600)
        directory=os.open(target.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
        body={'kind':'FreshDeploymentRestore','schema_version':schema_version,'source_backup_digest':source_digest,'consistent_backup_digest':backup_digest,'restored_digest':digest_bytes(target.read_bytes()),'old_epoch':old,'new_epoch':new_epoch,'trust_revision':revision+1,'revoked_approvals':revoked,'cancelled_runs':cancelled,'qualification':'not_qualified','old_instance_qualifications_valid':False,'integrity_check':'ok','source_unchanged':True};body['digest']=digest_jcs(body);return body
    finally:
        temporary.unlink(missing_ok=True)
