"""Open archived originals without following any path component symlink."""
import os
from pathlib import Path
import stat


def open_original(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or path==Path('/'):
        raise ValueError('archive_original_absolute_canonical_path')
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory);directory=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
            os.close(fd)
            raise PermissionError('archive_original_regular_single_link')
        return fd
    finally:
        os.close(directory)


def identity(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,
            info.st_uid,info.st_gid,info.st_mode,info.st_nlink)


def require_unchanged(path,before,after):
    # Reopen through the complete component chain. A replacement path cannot
    # pass merely because the original already-open descriptor stayed stable.
    fd=open_original(path)
    try:current=os.fstat(fd)
    finally:os.close(fd)
    if identity(before)!=identity(after) or identity(before)!=identity(current):
        raise ValueError('archive_original_path_or_bytes_changed')
