"""Bounded Gate reads of explicitly granted original evidence bytes."""
import os
from pathlib import Path
import stat


def read_granted_raw(path, *, uid, gid, limit):
    path = Path(path)
    parent = path.parent.lstat()
    if (not path.is_absolute() or path.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
            or parent.st_gid != gid or stat.S_IMODE(parent.st_mode) != 0o750):
        raise PermissionError('raw_evidence_directory_custody')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
                or before.st_gid != gid or stat.S_IMODE(before.st_mode) != 0o640
                or before.st_nlink != 1 or before.st_size > limit):
            raise PermissionError('raw_evidence_file_custody')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        current = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns)
    if (len(raw) != before.st_size or len(raw) > limit
            or identity(before) != identity(after)
            or identity(before) != identity(current)):
        raise ValueError('raw_evidence_changed_during_review')
    return raw
