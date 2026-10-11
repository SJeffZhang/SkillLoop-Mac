"""Trusted host caller for one frozen formal-CLI whole-round attempt.

The launcher connects the Linux pre-operator bootstrap, the original native
backend parent and the installed CLI frontend.  It records intent before every
Docker or process effect.  A restarted launcher only inspects the original
objects; it never starts a replacement campaign or native backend.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from skillloop.protocol import decode_json, digest_jcs
from skillloop.runtime.docker_api import DockerEngine, DockerEngineError
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.whole_source import whole_source_index


def _owned_document(path, *, uid, maximum=2097152):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.is_symlink():
        raise PermissionError('whole_round_host_canonical_document')
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
            or stat.S_IMODE(parent.st_mode) != 0o700):
        raise PermissionError('whole_round_host_private_parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > maximum):
            raise PermissionError('whole_round_host_document_custody')
        value = decode_json(stream.read(maximum + 1))
    if (type(value) is not dict
            or value.get('digest') != digest_jcs({k: v for k, v in value.items() if k != 'digest'})):
        raise ValueError('whole_round_host_document_seal')
    return value


def _host_config(config, *, image, role, epoch, command, user):
    fields = {'Image', 'User', 'Entrypoint', 'Cmd', 'Env', 'Labels', 'HostConfig'}
    if (type(config) is not dict or set(config) != fields
            or config['Image'] != image or config['User'] != user
            or config['Entrypoint'] != command[0] or config['Cmd'] != command[1]
            or config['Labels'] != {'skillloop.deployment_epoch': epoch, 'skillloop.role': role}
            or type(config['Env']) is not list
            or len(config['Env']) != len(set(config['Env']))
            or any(type(item) is not str or '=' not in item or '\x00' in item for item in config['Env'])):
        raise ValueError('whole_round_host_exact_container_configuration')
    host = config['HostConfig']
    required = {'NetworkMode', 'ReadonlyRootfs', 'CapDrop', 'SecurityOpt', 'Memory',
                'NanoCpus', 'PidsLimit', 'Ulimits', 'RestartPolicy', 'LogConfig',
                'Tmpfs', 'Mounts'}
    if (type(host) is not dict or set(host) != required
            or host['NetworkMode'] != 'none' or host['ReadonlyRootfs'] is not True
            or host['CapDrop'] != ['ALL'] or host['SecurityOpt'] != ['no-new-privileges']
            or host['Memory'] != 1073741824 or host['NanoCpus'] != 2000000000
            or host['PidsLimit'] != 64
            or host['Ulimits'] != [{'Name': 'nofile', 'Soft': 128, 'Hard': 128}]
            or host['RestartPolicy'] != {'Name': 'no'}
            or host['LogConfig'] != {'Type': 'none', 'Config': {}}
            or host['Tmpfs'] != {'/tmp': 'rw,nosuid,nodev,size=64m'}
            or type(host['Mounts']) is not list or not host['Mounts']):
        raise ValueError('whole_round_host_restricted_container')
    targets = set()
    for mount in host['Mounts']:
        if (type(mount) is not dict or set(mount) - {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'}
                or mount.get('Type') not in {'bind', 'volume'}
                or type(mount.get('Source')) is not str or type(mount.get('Target')) is not str
                or not mount['Target'].startswith('/') or '..' in Path(mount['Target']).parts
                or type(mount.get('ReadOnly')) is not bool or mount['Target'] in targets):
            raise ValueError('whole_round_host_exact_mount')
        targets.add(mount['Target'])
    return {mount['Target']: mount for mount in host['Mounts']}


def _read_policy(path):
    uid = os.geteuid()
    policy = _owned_document(path, uid=uid)
    fields = {'kind', 'campaign_digest', 'deployment_epoch', 'image', 'source_digest',
              'docker_socket', 'bootstrap_name', 'bootstrap_launch_path', 'bootstrap_launch_digest',
              'bootstrap_config',
              'native_host_policy_path', 'frontend_name', 'frontend_config',
              'bootstrap_timeout_seconds', 'frontend_timeout_seconds', 'deadline',
              'journal_directory', 'digest'}
    if (set(policy) != fields or policy['kind'] != 'FrozenWholeRoundHostLaunch'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['campaign_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['image'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['source_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', policy['bootstrap_launch_digest'])
            or not re.fullmatch(r'skillloop-bootstrap-[0-9a-f]{24}', policy['bootstrap_name'])
            or not re.fullmatch(r'skillloop-frontend-[0-9a-f]{24}', policy['frontend_name'])
            or type(policy['bootstrap_timeout_seconds']) is not int
            or not 60 <= policy['bootstrap_timeout_seconds'] <= 1200
            or type(policy['frontend_timeout_seconds']) is not int
            or not 60 <= policy['frontend_timeout_seconds'] <= 28800):
        raise ValueError('whole_round_host_frozen_identity')
    for name in ('docker_socket', 'bootstrap_launch_path', 'native_host_policy_path',
                 'journal_directory'):
        value = Path(policy[name])
        if not value.is_absolute() or '..' in value.parts or str(value) != policy[name]:
            raise ValueError('whole_round_host_canonical_path')
    deadline = datetime.fromisoformat(policy['deadline'].replace('Z', '+00:00'))
    if (deadline.tzinfo is None or not 120 < (deadline - datetime.now(timezone.utc)).total_seconds() <= 28800):
        raise ValueError('whole_round_host_original_clock')
    source = digest_jcs(whole_source_index(Path(__file__).resolve().parents[2]))
    if source != policy['source_digest']:
        raise ValueError('whole_round_host_actual_source_changed')
    native = _owned_document(policy['native_host_policy_path'], uid=uid)
    if (native.get('kind') != 'FrozenNativeRoundHostLaunch'
            or native.get('campaign_id') != policy['campaign_digest']
            or native.get('deployment_epoch') != policy['deployment_epoch']
            or native.get('bootstrap_name') != policy['bootstrap_name']
            or native.get('bootstrap_image') != policy['image']
            or native.get('docker_socket') != policy['docker_socket']
            or native.get('deadline') != policy['deadline']):
        raise ValueError('whole_round_host_cross_phase_binding')
    bootstrap_mounts = _host_config(policy['bootstrap_config'], image=policy['image'],
        role='bootstrap', epoch=policy['deployment_epoch'],
        command=(['python'], ['-m', 'skillloop.runtime.pre_operator_bootstrap']), user='0:0')
    launch_mount = bootstrap_mounts.get('/bootstrap-input')
    engine_mount = bootstrap_mounts.get('/engine.sock')
    if (launch_mount is None or launch_mount.get('Type') != 'bind'
            or launch_mount.get('ReadOnly') is not True
            or Path(policy['bootstrap_launch_path']).parent != Path(launch_mount['Source'])
            or Path(policy['bootstrap_launch_path']).name != 'launch.json'
            or engine_mount != {'Type': 'bind', 'Source': policy['docker_socket'],
                                'Target': '/engine.sock', 'ReadOnly': False}):
        raise ValueError('whole_round_host_bootstrap_original_inputs')
    frontend = policy['frontend_config']
    if (type(frontend) is not dict or type(frontend.get('User')) is not str
            or not re.fullmatch(r'([0-9]+):\1', frontend['User'])):
        raise ValueError('whole_round_host_frontend_identity')
    uid_text = frontend['User'].split(':', 1)[0]
    if int(uid_text) in {0, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21011}:
        raise PermissionError('whole_round_host_frontend_operator_or_admin_only')
    frontend_mounts = _host_config(frontend, image=policy['image'], role='operator_frontend',
        epoch=policy['deployment_epoch'], command=(['skillloop'], frontend['Cmd']), user=frontend['User'])
    if (not frontend['Cmd'] or frontend['Cmd'][0] not in {
            'import', 'scan', 'evaluate', 'harden', 'report', 'promote', 'inspect', 'admin'}
            or '/etc/skillloop' not in frontend_mounts
            or frontend_mounts['/etc/skillloop'].get('ReadOnly') is not True
            or any(mount.get('Target') in {'/engine.sock', '/var/run/docker.sock'}
                   for mount in frontend_mounts.values())):
        raise PermissionError('whole_round_host_installed_formal_frontend_only')
    policy['_deadline'] = deadline
    return policy


def _inspect_config(actual, *, identifier, name, config):
    if (actual.get('Id') != identifier or actual.get('Name') != '/' + name
            or actual.get('Image') != config['Image']
            or any(actual.get('Config', {}).get(key) != config[key]
                   for key in ('User', 'Entrypoint', 'Cmd', 'Labels'))):
        raise ValueError('whole_round_host_original_container_changed')
    host = actual.get('HostConfig', {})
    expected = config['HostConfig']
    if (host.get('NetworkMode') != expected['NetworkMode']
            or host.get('ReadonlyRootfs') is not True
            or {item.removeprefix('CAP_') for item in host.get('CapDrop') or []} != {'ALL'}
            or host.get('Privileged') is not False or host.get('Binds') or host.get('Devices')):
        raise ValueError('whole_round_host_original_restrictions_changed')
    return actual


def _create_original(engine, root, *, label, name, config):
    intent = _save(root, label + '-create-intent.json', {'kind': 'WholeRoundContainerCreateIntent',
        'container_name': name, 'configuration': config, 'automatic_reexecution_allowed': False})
    try:
        identifier = engine.create(name, config, timeout=30)
        actual = _inspect_config(engine.inspect(identifier, timeout=5), identifier=identifier,
                                 name=name, config=config)
        return _save(root, label + '-created.json', {'kind': 'WholeRoundContainerCreated',
            'intent_digest': intent['digest'], 'container_id': identifier, 'inspection': actual})
    except BaseException as error:
        unknown = {'kind': 'WholeRoundContainerUnknownCreation', 'intent_digest': intent['digest'],
            'container_name': name, 'automatic_reexecution_allowed': False,
            'error_type': type(error).__name__}
        try:
            actual = engine.inspect(name, timeout=5)
            _inspect_config(actual, identifier=actual['Id'], name=name, config=config)
            unknown['inspection'] = actual
        except BaseException as observation:
            unknown['observation_error_type'] = type(observation).__name__
        _save(root, label + '-creation-unknown.json', unknown)
        raise


def _start_original(engine, root, *, label, created, name, config):
    intent = _save(root, label + '-start-intent.json', {'kind': 'WholeRoundContainerStartIntent',
        'created_digest': created['digest'], 'container_id': created['container_id'],
        'automatic_reexecution_allowed': False})
    try:
        engine.start(created['container_id'], timeout=30)
    except BaseException as error:
        actual = engine.inspect(created['container_id'], timeout=5)
        _inspect_config(actual, identifier=created['container_id'], name=name, config=config)
        _save(root, label + '-start-unknown.json', {'kind': 'WholeRoundContainerUnknownStart',
            'intent_digest': intent['digest'], 'inspection': actual,
            'automatic_reexecution_allowed': False, 'error_type': type(error).__name__})
        if actual.get('State', {}).get('StartedAt') in {None, '0001-01-01T00:00:00Z'}:
            raise
    actual = _inspect_config(engine.inspect(created['container_id'], timeout=5),
        identifier=created['container_id'], name=name, config=config)
    if actual.get('State', {}).get('StartedAt') in {None, '0001-01-01T00:00:00Z'}:
        raise RuntimeError('whole_round_host_original_start_unobserved')
    return _save(root, label + '-started.json', {'kind': 'WholeRoundContainerStarted',
        'intent_digest': intent['digest'], 'inspection': actual})


def recover(policy_path):
    """Inspect a prior launch without recreating a container or backend."""
    policy = _read_policy(policy_path)
    root = Path(policy['journal_directory'])
    if not root.exists():
        raise FileNotFoundError('whole_round_host_launch_not_started')
    engine = DockerEngine(policy['docker_socket'])
    result = {'kind': 'WholeRoundHostRecoveryObservation', 'launch_digest': policy['digest'],
              'automatic_reexecution_allowed': False, 'containers': {}}
    for label, name in (('bootstrap', policy['bootstrap_name']),
                        ('frontend', policy['frontend_name'])):
        try:
            actual = engine.inspect(name, timeout=5)
        except DockerEngineError as error:
            if error.status != 404:
                raise
            result['containers'][label] = {'status': 'missing'}
        else:
            config = policy[label + '_config']
            _inspect_config(actual, identifier=actual['Id'], name=name, config=config)
            result['containers'][label] = {'status': actual['State']['Status'],
                                           'id': actual['Id'], 'exit_code': actual['State']['ExitCode']}
    result['native_host_status'] = ('closed' if (root / 'native-host-exited.json').exists()
                                    else 'unknown_preserve_original')
    result['digest'] = digest_jcs(result)
    return result


def run(policy_path):
    policy = _read_policy(policy_path)
    root = Path(policy['journal_directory'])
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = root.lstat()
    if (root.is_symlink() or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise PermissionError('whole_round_host_journal_custody')
    if any(root.iterdir()):
        raise RuntimeError('whole_round_host_existing_intent_use_recover')
    engine = DockerEngine(policy['docker_socket'])
    _save(root, 'launch-intent.json', {'kind': 'WholeRoundHostIntent',
        'launch_digest': policy['digest'], 'campaign_digest': policy['campaign_digest'],
        'source_digest': policy['source_digest'], 'image': policy['image'],
        'automatic_reexecution_allowed': False})
    bootstrap = _create_original(engine, root, label='bootstrap',
        name=policy['bootstrap_name'], config=policy['bootstrap_config'])
    _start_original(engine, root, label='bootstrap', created=bootstrap,
        name=policy['bootstrap_name'], config=policy['bootstrap_config'])
    waited = engine.wait(bootstrap['container_id'], policy['bootstrap_timeout_seconds'])
    actual = _inspect_config(engine.inspect(bootstrap['container_id'], timeout=5),
        identifier=bootstrap['container_id'], name=policy['bootstrap_name'],
        config=policy['bootstrap_config'])
    if waited.get('StatusCode') != 0 or actual.get('State', {}).get('ExitCode') != 0:
        raise RuntimeError('whole_round_host_bootstrap_failed_preserve_resources')
    # The root-owned launch is intentionally unreadable to the ordinary host
    # administrator.  Read the original bytes back through the stopped Linux
    # bootstrap and validate their container ownership before continuing.
    from skillloop.runtime.native_round_host import _bootstrap_owned_json
    original_launch = _bootstrap_owned_json(engine, bootstrap['container_id'],
        '/bootstrap-input/launch.json', uid=0, gid=None, mode=0o600)
    native_policy = _owned_document(policy['native_host_policy_path'], uid=os.geteuid())
    if (original_launch.get('kind') != 'FrozenPreOperatorLaunch'
            or original_launch['digest'] != policy['bootstrap_launch_digest']
            or original_launch.get('campaign_digest') != policy['campaign_digest']
            or original_launch.get('deployment_epoch') != policy['deployment_epoch']
            or original_launch.get('deadline') != policy['deadline']
            or original_launch.get('native_host_launch_digest') != native_policy['digest']):
        raise ValueError('whole_round_host_original_bootstrap_launch_changed')
    _save(root, 'bootstrap-completed.json', {'kind': 'WholeRoundBootstrapCompleted',
        'container_id': bootstrap['container_id'], 'inspection': actual,
        'launch_digest': original_launch['digest']})
    stdout = os.open(root / 'native-host.stdout', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stderr = os.open(root / 'native-host.stderr', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    native_intent = _save(root, 'native-host-start-intent.json', {'kind': 'WholeRoundNativeHostStartIntent',
        'policy_digest': _owned_document(policy['native_host_policy_path'], uid=os.geteuid())['digest'],
        'automatic_reexecution_allowed': False})
    source_root = str(Path(__file__).resolve().parents[2])
    try:
        process = subprocess.Popen([sys.executable, '-m', 'skillloop.runtime.native_round_host',
            policy['native_host_policy_path']], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            close_fds=True, start_new_session=True, cwd=source_root,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'PYTHONPATH': source_root,
                 'PYTHONDONTWRITEBYTECODE': '1'})
    finally:
        os.close(stdout); os.close(stderr)
    _save(root, 'native-host-started.json', {'kind': 'WholeRoundNativeHostStarted',
        'intent_digest': native_intent['digest'], 'pid': process.pid,
        'automatic_reexecution_allowed': False})
    try:
        frontend = _create_original(engine, root, label='frontend',
            name=policy['frontend_name'], config=policy['frontend_config'])
        _start_original(engine, root, label='frontend', created=frontend,
            name=policy['frontend_name'], config=policy['frontend_config'])
        front_wait = engine.wait(frontend['container_id'], policy['frontend_timeout_seconds'])
        front_actual = _inspect_config(engine.inspect(frontend['container_id'], timeout=5),
            identifier=frontend['container_id'], name=policy['frontend_name'],
            config=policy['frontend_config'])
        if front_wait.get('StatusCode') != 0 or front_actual.get('State', {}).get('ExitCode') != 0:
            raise RuntimeError('whole_round_host_formal_cli_failed_preserve_original')
        remaining = max(1, (policy['_deadline'] - datetime.now(timezone.utc)).total_seconds())
        try:
            native_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise TimeoutError('whole_round_host_native_parent_still_live_preserve_original') from None
        _save(root, 'native-host-exited.json', {'kind': 'WholeRoundNativeHostExited',
            'pid': process.pid, 'exit_code': native_code, 'automatic_reexecution_allowed': False})
        if native_code != 0:
            raise RuntimeError('whole_round_host_native_parent_failed_preserve_original')
        return _save(root, 'completion.json', {'kind': 'WholeRoundHostCompletion',
            'launch_digest': policy['digest'], 'bootstrap_id': bootstrap['container_id'],
            'frontend_id': frontend['container_id'], 'native_host_pid': process.pid,
            'formal_cli_exit_code': front_actual['State']['ExitCode'],
            'qualification_issued': False, 'runtime_acceptance_complete': False})
    except BaseException as error:
        try:
            _save(root, 'failure.json', {'kind': 'WholeRoundHostFailure',
                'launch_digest': policy['digest'], 'native_host_pid': process.pid,
                'error_type': type(error).__name__, 'automatic_reexecution_allowed': False,
                'original_processes_preserved': True, 'qualification_issued': False})
        except BaseException as custody_error:
            error.add_note('whole_round_host_failure_custody:' + type(custody_error).__name__)
        raise


if __name__ == '__main__':
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(64)
    if len(sys.argv) == 3 and sys.argv[1] == '--recover':
        from skillloop.protocol import canonical_json_line
        sys.stdout.buffer.write(canonical_json_line(recover(sys.argv[2])))
    elif len(sys.argv) == 2:
        run(sys.argv[1])
    else:
        raise SystemExit(64)
