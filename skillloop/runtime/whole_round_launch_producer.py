"""Produce one executable host launch from an Admin-frozen declaration.

This producer fixes container restrictions and entrypoints in code.  The
declaration may choose only the already approved image, mounts, formal CLI
arguments and bounded clocks; it cannot inject another executable or network.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from skillloop.protocol import canonical_json_line, digest_jcs
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.whole_round_launcher import _owned_document
from skillloop.runtime.whole_source import whole_source_index


def _mounts(value, *, docker_socket=None, launch_directory=None):
    if type(value) is not list or len(value) > 64:
        raise ValueError('whole_round_launch_mount_inventory')
    mounts = []
    for item in value:
        if (type(item) is not dict or set(item) - {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'}
                or item.get('Type') not in {'bind', 'volume'}
                or type(item.get('Source')) is not str or type(item.get('Target')) is not str
                or not item['Target'].startswith('/') or '..' in Path(item['Target']).parts
                or type(item.get('ReadOnly')) is not bool):
            raise ValueError('whole_round_launch_mount_shape')
        if item['Type'] == 'bind':
            source = Path(item['Source'])
            if not source.is_absolute() or '..' in source.parts or source.is_symlink():
                raise PermissionError('whole_round_launch_bind_source')
            if item.get('VolumeOptions') is not None:
                raise ValueError('whole_round_launch_bind_options')
        else:
            if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', item['Source'])
                    or type(item.get('VolumeOptions')) is not dict
                    or set(item['VolumeOptions']) != {'Subpath'}):
                raise ValueError('whole_round_launch_volume_pin')
            subpath = Path(item['VolumeOptions']['Subpath'])
            if subpath.is_absolute() or '..' in subpath.parts or str(subpath) in {'', '.'}:
                raise ValueError('whole_round_launch_volume_subpath')
        mounts.append(dict(item))
    fixed = []
    if docker_socket is not None:
        fixed.append({'Type': 'bind', 'Source': docker_socket, 'Target': '/engine.sock',
                      'ReadOnly': False})
    if launch_directory is not None:
        fixed.append({'Type': 'bind', 'Source': launch_directory, 'Target': '/bootstrap-input',
                      'ReadOnly': True})
    result = fixed + mounts
    targets = [item['Target'] for item in result]
    if len(targets) != len(set(targets)):
        raise ValueError('whole_round_launch_mount_target_conflict')
    if any(item['Target'] in {'/engine.sock', '/var/run/docker.sock'} for item in mounts):
        raise PermissionError('whole_round_launch_engine_mount_fixed')
    return result


def _container(*, image, user, role, epoch, entrypoint, command, mounts):
    return {'Image': image, 'User': user, 'Entrypoint': entrypoint, 'Cmd': command,
        'Env': ['PYTHONDONTWRITEBYTECODE=1',
                'PYTHONPATH=/code/scripts/vendor:/code:/opt/archive-crypto'],
        'Labels': {'skillloop.deployment_epoch': epoch, 'skillloop.role': role},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
            'SecurityOpt': ['no-new-privileges'], 'Memory': 1073741824,
            'NanoCpus': 2000000000, 'PidsLimit': 64,
            'Ulimits': [{'Name': 'nofile', 'Soft': 128, 'Hard': 128}],
            'RestartPolicy': {'Name': 'no'}, 'LogConfig': {'Type': 'none', 'Config': {}},
            'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=64m'}, 'Mounts': mounts}}


def _formal_command(arguments):
    if (type(arguments) is not list or not arguments or len(arguments) > 128
            or any(type(arg) is not str or not arg or '\x00' in arg or len(arg) > 4096
                   for arg in arguments)):
        raise ValueError('whole_round_launch_formal_arguments')
    profile = json.loads((Path(__file__).resolve().parents[2] /
        'specs/v2.2/operations/cli.json').read_text())
    names = {row['name'] for row in profile['commands']}
    command = arguments[0] if arguments[0] != 'admin' else (
        'admin ' + arguments[1] if len(arguments) > 1 else '')
    if command not in names:
        raise ValueError('whole_round_launch_frozen_cli_command')
    return arguments


def produce(policy_path):
    uid = os.geteuid()
    policy = _owned_document(policy_path, uid=uid)
    fields = {'kind', 'campaign_digest', 'deployment_epoch', 'image', 'source_digest',
        'docker_socket', 'bootstrap_name', 'bootstrap_launch_path', 'bootstrap_launch_digest',
        'native_host_policy_path', 'frontend_name', 'frontend_uid', 'frontend_arguments',
        'bootstrap_mounts', 'frontend_mounts', 'bootstrap_timeout_seconds',
        'frontend_timeout_seconds', 'deadline', 'journal_directory', 'output_path', 'digest'}
    if (set(policy) != fields or policy['kind'] != 'FrozenWholeRoundHostProductionPolicy'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['campaign_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['image'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['source_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['bootstrap_launch_digest'])
            or not re.fullmatch(r'skillloop-bootstrap-[0-9a-f]{24}', policy['bootstrap_name'])
            or not re.fullmatch(r'skillloop-frontend-[0-9a-f]{24}', policy['frontend_name'])
            or type(policy['frontend_uid']) is not int
            or policy['frontend_uid'] in {0, 21001, 21002, 21003, 21004, 21005,
                                          21006, 21007, 21008, 21009, 21011}
            or not 1 <= policy['frontend_uid'] <= 4294967294
            or type(policy['bootstrap_timeout_seconds']) is not int
            or not 60 <= policy['bootstrap_timeout_seconds'] <= 1200
            or type(policy['frontend_timeout_seconds']) is not int
            or not 60 <= policy['frontend_timeout_seconds'] <= 28800):
        raise ValueError('whole_round_launch_production_identity')
    paths = {}
    for name in ('docker_socket', 'bootstrap_launch_path', 'native_host_policy_path',
                 'journal_directory', 'output_path'):
        path = Path(policy[name])
        if not path.is_absolute() or '..' in path.parts or str(path) != policy[name]:
            raise ValueError('whole_round_launch_production_canonical_path')
        paths[name] = path
    if paths['output_path'].name != 'launch.json' or paths['output_path'].parent == paths['journal_directory']:
        raise ValueError('whole_round_launch_distinct_output_and_journal')
    socket_info = paths['docker_socket'].lstat()
    launch_info = paths['bootstrap_launch_path'].lstat()
    if (not stat.S_ISSOCK(socket_info.st_mode)
            or not stat.S_ISREG(launch_info.st_mode) or launch_info.st_uid != 0
            or launch_info.st_nlink != 1 or stat.S_IMODE(launch_info.st_mode) != 0o600
            or paths['bootstrap_launch_path'].name != 'launch.json'
            or paths['bootstrap_launch_path'].parent.is_symlink()):
        raise PermissionError('whole_round_launch_actual_root_bootstrap_input')
    native = _owned_document(paths['native_host_policy_path'], uid=uid)
    if (native.get('kind') != 'FrozenNativeRoundHostLaunch'
            or native.get('campaign_id') != policy['campaign_digest']
            or native.get('deployment_epoch') != policy['deployment_epoch']
            or native.get('bootstrap_name') != policy['bootstrap_name']
            or native.get('bootstrap_image') != policy['image']
            or native.get('docker_socket') != policy['docker_socket']
            or native.get('deadline') != policy['deadline']):
        raise ValueError('whole_round_launch_native_policy_binding')
    deadline = datetime.fromisoformat(policy['deadline'].replace('Z', '+00:00'))
    if deadline.tzinfo is None or not 120 < (deadline - datetime.now(timezone.utc)).total_seconds() <= 28800:
        raise ValueError('whole_round_launch_original_clock')
    source = digest_jcs(whole_source_index(Path(__file__).resolve().parents[2]))
    if source != policy['source_digest']:
        raise ValueError('whole_round_launch_actual_source_changed')
    image = DockerEngine(policy['docker_socket']).inspect_image(policy['image'], timeout=10)
    if (image.get('Id') != policy['image'] or image.get('Os') != 'linux'
            or image.get('Architecture') != 'arm64'):
        raise ValueError('whole_round_launch_actual_linux_arm64_image')
    bootstrap_mounts = _mounts(policy['bootstrap_mounts'], docker_socket=policy['docker_socket'],
        launch_directory=str(paths['bootstrap_launch_path'].parent))
    frontend_mounts = _mounts(policy['frontend_mounts'])
    if (not any(item['Target'] == '/etc/skillloop' and item['ReadOnly'] is True
                for item in frontend_mounts)
            or any(item['Type'] == 'bind' for item in frontend_mounts)):
        raise PermissionError('whole_round_launch_frontend_volume_only_configuration')
    bootstrap = _container(image=policy['image'], user='0:0', role='bootstrap',
        epoch=policy['deployment_epoch'], entrypoint=['python'],
        command=['-m', 'skillloop.runtime.pre_operator_bootstrap'], mounts=bootstrap_mounts)
    frontend = _container(image=policy['image'],
        user=str(policy['frontend_uid']) + ':' + str(policy['frontend_uid']),
        role='operator_frontend', epoch=policy['deployment_epoch'], entrypoint=['skillloop'],
        command=_formal_command(policy['frontend_arguments']), mounts=frontend_mounts)
    value = {'kind': 'FrozenWholeRoundHostLaunch',
        **{name: policy[name] for name in ('campaign_digest', 'deployment_epoch', 'image',
            'source_digest', 'docker_socket', 'bootstrap_name', 'bootstrap_launch_path',
            'bootstrap_launch_digest', 'native_host_policy_path', 'frontend_name',
            'bootstrap_timeout_seconds', 'frontend_timeout_seconds', 'deadline',
            'journal_directory')},
        'bootstrap_config': bootstrap, 'frontend_config': frontend}
    value['digest'] = digest_jcs(value)
    target = paths['output_path']; parent = target.parent.lstat()
    if (target.parent.is_symlink() or parent.st_uid != uid or stat.S_IMODE(parent.st_mode) != 0o700):
        raise PermissionError('whole_round_launch_output_custody')
    raw = canonical_json_line(value)
    if target.exists():
        if _owned_document(target, uid=uid) != value:
            raise ValueError('whole_round_launch_original_output_changed')
    else:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
    return value


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        raise SystemExit(64)
    produce(sys.argv[1])
