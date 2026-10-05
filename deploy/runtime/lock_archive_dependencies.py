"""Build-time Linux lock producer for hash-verified, offline crypto wheels.

Run after pip --no-index --require-hashes --no-compile into a fresh target.
The wheels and complete actual installed inventory remain separate pins.
"""
import hashlib
import importlib.metadata
import os
from pathlib import Path,PurePosixPath
import platform
import stat
import sys

from skillloop.protocol import canonical_json_line,decode_json,digest_jcs


def produce(artifact_path,wheel_directory,installed_directory,output_path):
    if platform.system()!='Linux' or platform.machine() not in {'aarch64','arm64'}:
        raise ValueError('crypto_lock_target_linux_aarch64_required')
    artifacts=decode_json(Path(artifact_path).read_bytes())
    if (set(artifacts)!={'kind','platform','distributions','digest'}
            or artifacts['kind']!='FrozenArchiveWheelArtifacts' or artifacts['platform']!='linux-aarch64'
            or artifacts['digest']!=digest_jcs({k:v for k,v in artifacts.items() if k!='digest'})
            or set(artifacts['distributions'])!={'cryptography','cffi','pycparser','typing_extensions'}):
        raise ValueError('crypto_lock_complete_artifact_manifest')
    root=Path(installed_directory).resolve(strict=True);wheels=Path(wheel_directory)
    distributions={d.metadata['Name'].replace('-','_').lower():d
        for d in importlib.metadata.distributions(path=[str(root)])}
    if set(distributions)!=set(artifacts['distributions']):raise ValueError('crypto_lock_installed_distribution_set')
    pins={}
    for name,pin in artifacts['distributions'].items():
        if (set(pin)!={'version','filename','digest'} or Path(pin['filename']).name!=pin['filename']
                or not pin['filename'].endswith('.whl')):raise ValueError('crypto_lock_safe_wheel_pin')
        wheel=wheels/pin['filename']
        if wheel.is_symlink() or 'sha256:'+hashlib.sha256(wheel.read_bytes()).hexdigest()!=pin['digest']:
            raise ValueError('crypto_lock_original_wheel_bytes')
        distribution=distributions[name]
        if distribution.version!=pin['version']:raise ValueError('crypto_lock_installed_version')
        inventory={}
        for relative in distribution.files or []:
            value=str(relative);path=PurePosixPath(value)
            if (path.is_absolute() or '..' in path.parts or str(path)!=value
                    or value.endswith(('.pyc','.pyo'))):raise ValueError('crypto_lock_unapproved_installed_path')
            source=root/value
            if source.is_symlink() or not source.resolve(strict=True).is_relative_to(root):
                raise ValueError('crypto_lock_installed_symlink')
            info=source.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size>67108864:raise ValueError('crypto_lock_installed_capacity')
            inventory[value]='sha256:'+hashlib.sha256(source.read_bytes()).hexdigest()
        if not inventory:raise ValueError('crypto_lock_empty_installed_inventory')
        pins[name]={'version':pin['version'],'wheel_digest':pin['digest'],'files':inventory}
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual!={n for p in pins.values() for n in p['files']}:
        raise ValueError('crypto_lock_unlisted_installed_files')
    value={'kind':'FrozenArchiveCryptoDependencies','platform':'linux-aarch64','distributions':pins}
    value['digest']=digest_jcs(value)
    fd=os.open(output_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as stream:stream.write(canonical_json_line(value));stream.flush();os.fsync(stream.fileno())
    return value


if __name__=='__main__':
    if len(sys.argv)!=5:raise SystemExit('expected artifact manifest, wheel root, installed root, lock output')
    produce(*sys.argv[1:])
