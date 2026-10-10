"""Trusted host transfer of the original model lifecycle into Admin custody.

This sidecar has only the already-provisioned Admin input subpath and no
network, engine socket or private Factory volume. A lost create/upload reply
preserves the original container and bytes; it never sends a replacement PUT.
"""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

from skillloop.protocol import digest_jcs
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.native_backend import _owned
from skillloop.runtime.native_round_host import _save


NAMES = ('export.json', 'evidence.json', 'development-backend.log')
MAXIMUM = 75497472


def _source(root):
    root = Path(root)
    _owned(root, os.geteuid(), 0o700, directory=True)
    if {item.name for item in root.iterdir()} != set(NAMES):
        raise ValueError('native_admin_transfer_complete_original_export_required')
    values = {}
    for name in NAMES:
        path = root / name
        info = _owned(path, os.geteuid(), 0o600)
        if info.st_size > MAXIMUM:
            raise ValueError('native_admin_transfer_original_file_capacity')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(MAXIMUM + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or before.st_ino != info.st_ino
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                   (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('native_admin_transfer_original_bytes_changed')
        values[name] = raw
    if sum(map(len, values.values())) > MAXIMUM:
        raise ValueError('native_admin_transfer_total_original_capacity')
    return values


def _archive(values):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in NAMES:
            info = tarfile.TarInfo(name)
            info.uid = 21010
            info.gid = 21010
            info.uname = ''
            info.gname = ''
            info.mode = 0o600
            info.size = len(values[name])
            info.mtime = 0
            archive.addfile(info, io.BytesIO(values[name]))
    data = stream.getvalue()
    if len(data) > MAXIMUM + 32768:
        raise ValueError('native_admin_transfer_tar_capacity')
    return data


def _read_back(engine, identifier, name, original):
    tar = engine.archive(identifier, '/input/' + name,
                         maximum_bytes=len(original) + 16384)
    with tarfile.open(fileobj=io.BytesIO(tar), mode='r:') as archive:
        members = archive.getmembers()
        if len(members) != 1:
            raise ValueError('native_admin_transfer_exact_target_file')
        member = members[0]
        if (not member.isfile() or Path(member.name).name != name
                or member.uid != 21010 or member.gid != 21010
                or stat.S_IMODE(member.mode) != 0o600
                or member.size != len(original)):
            raise PermissionError('native_admin_transfer_actual_admin_custody')
        source = archive.extractfile(member)
        if source is None or source.read(len(original) + 1) != original:
            raise ValueError('native_admin_transfer_original_target_mismatch')


def _directory_members(engine, identifier, maximum_bytes):
    raw = engine.archive(identifier, '/input', maximum_bytes=maximum_bytes)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        roots = [m for m in members if m.isdir() and m.name.rstrip('/') in {'input', './input'}]
        if len(roots) != 1:
            raise ValueError('native_admin_transfer_exact_destination_directory')
        files = []
        for member in members:
            if member is roots[0]:
                continue
            if not member.isfile() or Path(member.name).parent.name != 'input':
                raise ValueError('native_admin_transfer_unexpected_destination_entry')
            files.append(Path(member.name).name)
        return sorted(files)


def transfer_original_export(*, engine, launch, receipt, journal):
    if type(engine) is not DockerEngine or receipt.get('kind') != 'NativeHostLifecycleExport':
        raise ValueError('native_admin_transfer_original_export_required')
    volume = launch['admin_input_volume']
    subpath = launch['admin_input_subpath']
    p = PurePosixPath(subpath)
    if (type(volume) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', volume)
            or type(subpath) is not str or p.is_absolute() or '..' in p.parts
            or str(p) != subpath or subpath in {'', '.'}):
        raise ValueError('native_admin_transfer_frozen_volume')
    values = _source(launch['export_directory'])
    inventory = {name: {'bytes': len(values[name]),
                        'digest': 'sha256:' + hashlib.sha256(values[name]).hexdigest()}
                 for name in NAMES}
    if (receipt['files'] != {name: inventory[name] for name in NAMES if name != 'export.json'}
            or receipt['campaign_id'] != launch['campaign_id']
            or receipt['deployment_epoch'] != launch['deployment_epoch']):
        raise ValueError('native_admin_transfer_original_receipt_binding')
    data = _archive(values)
    name = 'skillloop-native-import-' + launch['digest'][7:31]
    config = {'Image': launch['controller_image'], 'User': '0:0',
        'Entrypoint': ['python'], 'Cmd': ['-c', 'import time; time.sleep(120)'],
        'Env': ['PYTHONDONTWRITEBYTECODE=1'],
        'Labels': {'skillloop.role': 'trusted_native_admin_transfer',
                   'skillloop.deployment_epoch': launch['deployment_epoch'],
                   'skillloop.launch_digest': launch['digest']},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True,
            'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
            'Memory': 134217728, 'NanoCpus': 1000000000, 'PidsLimit': 16,
            'RestartPolicy': {'Name': 'no'},
            'LogConfig': {'Type': 'none', 'Config': {}},
            'Mounts': [{'Type': 'volume', 'Source': volume, 'Target': '/input',
                        'ReadOnly': False, 'VolumeOptions': {'Subpath': subpath}}]}}
    _save(journal, 'transfer-intent.json', {'kind': 'NativeAdminTransferIntent',
        'launch_digest': launch['digest'], 'export_digest': receipt['digest'],
        'inventory': inventory, 'container_name': name,
        'configuration_digest': digest_jcs(config),
        'automatic_reexecution_allowed': False})
    identifier = engine.create(name, config, timeout=30)
    _save(journal, 'transfer-created.json', {'kind': 'NativeAdminTransferCreated',
        'container_id': identifier, 'container_name': name})
    actual = engine.inspect(identifier)
    if (actual.get('Id') != identifier or actual.get('Image') != launch['controller_image']
            or actual.get('Config', {}).get('Labels') != config['Labels']
            or actual.get('Config', {}).get('User') != '0:0'
            or len(actual.get('Mounts', [])) != 1
            or actual['Mounts'][0].get('Type') != 'volume'
            or actual['Mounts'][0].get('Name') != volume
            or actual['Mounts'][0].get('Destination') != '/input'
            or actual['Mounts'][0].get('RW') is not True
            or actual.get('HostConfig', {}).get('Mounts') != config['HostConfig']['Mounts']
            or actual.get('HostConfig', {}).get('NetworkMode') != 'none'
            or actual.get('HostConfig', {}).get('CapDrop') != ['ALL']):
        raise ValueError('native_admin_transfer_original_container_identity')
    engine.start(identifier)
    running = engine.inspect(identifier)
    if running.get('State', {}).get('Running') is not True:
        raise RuntimeError('native_admin_transfer_original_container_not_live')
    if _directory_members(engine, identifier, 1048576):
        raise RuntimeError('native_admin_transfer_destination_not_empty')
    _save(journal, 'upload-intent.json', {'kind': 'NativeAdminUploadIntent',
        'container_id': identifier, 'tar_digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
        'automatic_reexecution_allowed': False})
    # A lost response may mean the bytes were written. Preserve this container
    # and inspect it later; never issue a second PUT in this original round.
    engine.put_archive(identifier, '/input', data, timeout=30,
                       maximum_bytes=MAXIMUM + 32768)
    for item in NAMES:
        _read_back(engine, identifier, item, values[item])
    if _directory_members(engine, identifier, MAXIMUM + 32768) != sorted(NAMES):
        raise ValueError('native_admin_transfer_complete_destination_inventory')
    _save(journal, 'transfer-stop-intent.json', {'kind': 'NativeAdminTransferStopIntent',
        'container_id': identifier, 'original_bytes_verified': True})
    before = engine.inspect(identifier)
    if before.get('State', {}).get('Running') is True:
        engine.request('POST', '/containers/' + identifier + '/stop?t=1', timeout=5)
    stopped = engine.inspect(identifier)
    if (stopped.get('Id') != identifier or stopped.get('State', {}).get('Running') is not False
            or stopped.get('Mounts') != before.get('Mounts')):
        raise RuntimeError('native_admin_transfer_original_process_not_closed')
    completion = _save(journal, 'transfer-verified.json', {
        'kind': 'NativeAdminTransferVerified', 'container_id': identifier,
        'export_digest': receipt['digest'], 'inventory': inventory,
        'sidecar_stopped': True, 'admin_import_issued': False})
    # Keep the stopped original container for independent retirement review;
    # the retained volume's Keeper protects the bytes until the Gate archive.
    return completion
