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


def preserve_reviewed_raw(output_directory, sources, *, maximum_bytes):
    """Preserve successful review inputs; this is not an all-attempt inventory.

    Each source carries its expected decoded value or exact byte digest so a
    later reread cannot silently replace the bytes the Gate reviewed.
    """
    from skillloop.protocol import decode_json, digest_bytes
    from skillloop.runtime.archive_files import allocate_output
    output = Path(output_directory)
    info = output.lstat()
    if (os.geteuid() != 21005 or not output.is_absolute() or output.is_symlink()
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != 21005
            or info.st_gid != 21001 or stat.S_IMODE(info.st_mode) != 0o750
            or type(maximum_bytes) is not int or maximum_bytes < 1048576):
        raise PermissionError('raw_evidence_preservation_custody_or_budget')
    # Metadata and final review outputs retain a separate one MiB allowance.
    total = sum(p.stat().st_size for p in output.iterdir()
                if p.is_file() and not p.is_symlink())
    pins = []
    for source in sources:
        raw = read_granted_raw(source['path'], uid=source['uid'],
                               gid=source['gid'], limit=source['limit'])
        checksum = digest_bytes(raw)
        if (('value' in source and decode_json(raw) != source['value'])
                or ('bytes_digest' in source and checksum != source['bytes_digest'])):
            raise ValueError('raw_evidence_review_input_changed')
        name = 'reviewed-raw-' + checksum[7:] + '.bin'
        destination = output / name
        if destination.exists():
            if read_granted_raw(destination, uid=21005, gid=21001,
                                limit=source['limit']) != raw:
                raise ValueError('raw_evidence_existing_copy_conflict')
        else:
            if total + len(raw) + 1048576 > maximum_bytes:
                raise ValueError('raw_evidence_original_capacity_exhausted')
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'wb') as stream:
                allocate_output(stream.fileno(),len(raw))
                os.fchown(stream.fileno(), -1, 21001)
                os.fchmod(stream.fileno(), 0o640)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            total += len(raw)
        pins.append({'name': name, 'bytes_digest': checksum, 'size_bytes': len(raw),
                     'original_name': Path(source['path']).name,
                     'original_uid': source['uid'], 'original_gid': source['gid']})
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return pins


def verify_raw_pin(pin, directory):
    """Verify a roster-bound copy before campaign Gate consumption."""
    import re
    from skillloop.protocol import digest_bytes
    if (type(pin) is not dict or set(pin) != {'name','bytes_digest','size_bytes',
            'original_name','original_uid','original_gid'}
            or type(pin['bytes_digest']) is not str
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',pin['bytes_digest'])
            or pin['name'] != 'reviewed-raw-'+pin['bytes_digest'][7:]+'.bin'
            or type(pin['size_bytes']) is not int or not 0 <= pin['size_bytes'] <= 33554432):
        raise ValueError('campaign_gate_raw_input_pin')
    raw = read_granted_raw(Path(directory)/pin['name'],uid=21005,gid=21001,limit=33554432)
    if len(raw) != pin['size_bytes'] or digest_bytes(raw) != pin['bytes_digest']:
        raise ValueError('campaign_gate_raw_input_copy_changed')
    return raw


def preserve_private_raw_history(pins, source_directory, vault, *, maximum_bytes):
    """Copy reviewed roster bytes into the existing private Gate archive vault."""
    vault = Path(vault); info = vault.lstat()
    if (os.geteuid()!=21005 or vault.is_symlink() or not vault.is_absolute()
            or info.st_uid!=21005 or info.st_gid!=21005
            or stat.S_IMODE(info.st_mode)!=0o700 or type(pins) is not list
            or not 1<=len(pins)<=512 or type(maximum_bytes) is not int
            or not 1048576<=maximum_bytes<=268435456):
        raise PermissionError('campaign_gate_private_raw_history_budget_or_custody')
    total=sum(p.stat().st_size for p in vault.iterdir() if p.is_file() and not p.is_symlink())
    seen=set()
    for pin in pins:
        raw=verify_raw_pin(pin,source_directory)
        if pin['name'] in seen:continue
        seen.add(pin['name'])
        if total+len(raw)+1048576>maximum_bytes:
            raise ValueError('campaign_gate_private_raw_history_capacity')
        fd=os.open(vault/pin['name'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),-1,21005);os.fchmod(stream.fileno(),0o600)
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        total+=len(raw)
    fd=os.open(vault,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
