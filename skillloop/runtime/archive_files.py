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


def allocate_output(fd,length,*,free_floor_bytes=2147483648):
    """Allocate the actual output inode before writing its evidence bytes.

    This is a per-output allocation, not a complete campaign reservation.
    Failed or partially allocated files are retained for original recovery.
    """
    before=os.fstat(fd)
    if (type(length) is not int or not 0<=length<=2147483648
            or type(free_floor_bytes) is not int or free_floor_bytes<2147483648
            or not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
            or before.st_uid!=os.geteuid() or before.st_size!=0):
        raise PermissionError('archive_output_new_owned_inode_required')
    fs=os.fstatvfs(fd)
    if fs.f_bavail*fs.f_frsize<free_floor_bytes+length:
        raise OSError('archive_output_allocation_free_floor')
    if length:
        if not hasattr(os,'posix_fallocate'):
            raise RuntimeError('archive_output_real_allocation_unavailable')
        os.posix_fallocate(fd,0,length)
    os.fsync(fd);actual=os.fstat(fd);fs=os.fstatvfs(fd)
    if (actual.st_size!=length or actual.st_blocks*512<length
            or (actual.st_dev,actual.st_ino)!=(before.st_dev,before.st_ino)
            or fs.f_bavail*fs.f_frsize<free_floor_bytes):
        raise OSError('archive_output_real_allocation_or_floor_failed')
