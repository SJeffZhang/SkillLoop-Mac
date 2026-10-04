"""Locked cryptography backend and authenticated streaming archive format.

Only ciphertext and a wrapped random data key cross the private role boundary.
The administrator's RSA private key never enters a Gate or Controller mount.
"""
import hashlib
import importlib.metadata
import importlib.util
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import struct

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs

MAGIC=b'SL-AESGCM-1\n'
MAX_HEADER=65536


def locked_crypto(lock):
    if (type(lock) is not dict or set(lock)!={'kind','platform','distributions','digest'}
            or lock['kind']!='FrozenArchiveCryptoDependencies'
            or lock['digest']!=digest_jcs({k:v for k,v in lock.items() if k!='digest'})
            or lock['platform']!='linux-aarch64'
            or platform.system()!='Linux' or platform.machine() not in {'aarch64','arm64'}
            or type(lock['distributions']) is not dict
            or set(lock['distributions'])!={'cryptography','cffi','pycparser','typing_extensions'}):
        raise ValueError('archive_locked_linux_crypto_required')
    for name,pin in lock['distributions'].items():
        if (name not in {'cryptography','cffi','pycparser','typing_extensions'}
                or type(pin) is not dict or set(pin)!={'version','wheel_digest','files'}
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',pin['wheel_digest'])
                or type(pin['files']) is not dict or not 1<=len(pin['files'])<=4096):
            raise ValueError('archive_transitive_dependency_lock')
        distribution=importlib.metadata.distribution(name)
        if distribution.version!=pin['version']:raise ValueError('archive_dependency_version')
        root=Path(distribution.locate_file('')).absolute()
        installed={str(p) for p in distribution.files or [] if not str(p).endswith(('.pyc','.pyo'))}
        if installed!=set(pin['files']):raise ValueError('archive_dependency_complete_inventory')
        for relative,expected in pin['files'].items():
            path=PurePosixPath(relative)
            if path.is_absolute() or '..' in path.parts or str(path)!=relative:
                raise ValueError('archive_dependency_relative_file')
            source=root/relative
            if any(p.is_symlink() for p in (source,*source.parents)):
                raise ValueError('archive_dependency_symlink')
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                before=os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size>67108864:
                    raise ValueError('archive_dependency_regular_bounded_file')
                checksum=hashlib.sha256()
                for block in iter(lambda:stream.read(1048576),b''):checksum.update(block)
                after=os.fstat(stream.fileno())
            if ('sha256:'+checksum.hexdigest()!=expected or
                    (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns)):
                raise ValueError('archive_dependency_bytes_changed')
        # Wheel installations for this deployment must use --no-compile.
        # Unlocked bytecode and unlisted package files cannot be imported.
        package=root/name
        if package.is_dir():
            actual=set()
            for path in package.rglob('*'):
                if path.is_symlink():raise ValueError('archive_dependency_package_symlink')
                if path.is_file():
                    if path.suffix in {'.pyc','.pyo'}:raise ValueError('archive_dependency_unlocked_bytecode')
                    actual.add(path.relative_to(root).as_posix())
            expected={p for p in pin['files'] if p.startswith(name+'/')}
            if actual!=expected:raise ValueError('archive_dependency_unlisted_package_file')
        if any((root/'__pycache__').glob(name+'.*.pyc')):
            raise ValueError('archive_dependency_unlocked_module_bytecode')
        # Refuse a shadow module ahead of the approved installed distribution.
        module={'typing_extensions':'typing_extensions'}.get(name,name)
        spec=importlib.util.find_spec(module)
        if spec is None or spec.origin is None or Path(spec.origin).absolute().parent!=root/module and not str(Path(spec.origin).absolute()).startswith(str(root/module)+os.sep):
            if spec is None or spec.origin is None or Path(spec.origin).absolute()!=root/(module+'.py'):
                raise ValueError('archive_dependency_import_shadow')
        if Path(spec.origin).absolute().relative_to(root).as_posix() not in pin['files']:
            raise ValueError('archive_dependency_unlocked_import_origin')
    backend=importlib.util.find_spec('_cffi_backend')
    root=Path(importlib.metadata.distribution('cffi').locate_file('')).absolute()
    if (backend is None or backend.origin is None or Path(backend.origin).absolute().parent!=root
            or Path(backend.origin).name not in lock['distributions']['cffi']['files']):
        raise ValueError('archive_dependency_native_backend_shadow')
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import padding,rsa
    from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
    return hashes,serialization,padding,rsa,Cipher,algorithms,modes


def header_bytes(header):
    if (type(header) is not dict or set(header)!={'kind','campaign','deployment_epoch','operation_ref',
            'source_manifest_digest','dependency_lock_digest','key_id','wrapped_key','nonce'}
            or header['kind']!='AES256GCMArchiveHeader'
            or any(not re.fullmatch(r'sha256:[0-9a-f]{64}',header[k]) for k in
                ('campaign','source_manifest_digest','dependency_lock_digest','key_id'))
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',header['operation_ref'])
            or type(header['deployment_epoch']) is not str or not 1<=len(header['deployment_epoch'])<=256
            or not re.fullmatch(r'[0-9a-f]{768}',header['wrapped_key'])
            or not re.fullmatch(r'[0-9a-f]{24}',header['nonce'])):
        raise ValueError('archive_authenticated_header_shape')
    raw=canonical_json_line(header)
    if len(raw)>MAX_HEADER:raise ValueError('archive_header_capacity')
    return raw


def key_label(header):
    return canonical_json_line({k:v for k,v in header.items() if k not in {'wrapped_key','nonce'}})


def read_header(stream):
    if stream.read(len(MAGIC))!=MAGIC:raise ValueError('archive_format')
    size=stream.read(4)
    if len(size)!=4:raise ValueError('archive_truncated_header')
    count=struct.unpack('>I',size)[0]
    if not 1<=count<=MAX_HEADER:raise ValueError('archive_header_capacity')
    raw=stream.read(count)
    if len(raw)!=count:raise ValueError('archive_truncated_header')
    value=decode_json(raw)
    if header_bytes(value)!=raw:raise ValueError('archive_canonical_header_required')
    return value,raw


def encrypt_stream(*,output,chunks,header,key,crypto,budget):
    _,_,_,_,Cipher,algorithms,modes=crypto
    if type(key) is not bytes or len(key)!=32:raise ValueError('archive_AES256_key')
    raw=header_bytes(header);output.write(MAGIC+struct.pack('>I',len(raw))+raw)
    cipher=Cipher(algorithms.AES256(key),modes.GCM(bytes.fromhex(header['nonce']))).encryptor()
    cipher.authenticate_additional_data(raw)
    checksum=hashlib.sha256();total=0
    for chunk in chunks:
        budget();checksum.update(chunk);total+=len(chunk);output.write(cipher.update(chunk))
    output.write(cipher.finalize());output.write(cipher.tag)
    return 'sha256:'+checksum.hexdigest(),total


def verify_stream(*,source,key,crypto,expected_header,budget):
    """Authenticate the whole bundle before any caller may restore plaintext."""
    _,_,_,_,Cipher,algorithms,modes=crypto
    header,raw=read_header(source)
    if header!=expected_header or type(key) is not bytes or len(key)!=32:
        raise ValueError('archive_exact_original_header_key')
    start=source.tell();source.seek(0,2);end=source.tell()
    if end-start<16:raise ValueError('archive_missing_GCM_tag')
    source.seek(end-16);tag=source.read(16);source.seek(start)
    decryptor=Cipher(algorithms.AES256(key),modes.GCM(bytes.fromhex(header['nonce']),tag)).decryptor()
    decryptor.authenticate_additional_data(raw)
    checksum=hashlib.sha256();remaining=end-start-16;total=0
    while remaining:
        budget();block=source.read(min(1048576,remaining))
        if not block:raise ValueError('archive_truncated_ciphertext')
        clear=decryptor.update(block);checksum.update(clear);total+=len(clear);remaining-=len(block)
    clear=decryptor.finalize();checksum.update(clear);total+=len(clear)
    return 'sha256:'+checksum.hexdigest(),total
