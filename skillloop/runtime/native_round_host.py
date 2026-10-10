"""Original host caller for the development-to-private Ollama process switch.

The trusted host administrator starts this once before development. It reads
only the Controller-visible roster freeze and Factory commit from the original
Controller container; the complete private bundle never enters this process.
An ambiguous Docker read or backend start remains in the original journals.
"""
from datetime import datetime, timezone
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs
from skillloop.runtime.docker_api import DockerEngine, DockerEngineError
from skillloop.runtime.native_backend import NativeBackendSupervisor, _owned


def _read_policy(path):
    path = Path(path)
    uid = os.geteuid()
    _owned(path.parent, uid, 0o700, directory=True)
    info = _owned(path, uid, 0o600)
    if info.st_size > 262144:
        raise ValueError('native_round_host_policy_capacity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        value = decode_json(stream.read(262145))
    fields = {'kind', 'campaign_id', 'deployment_epoch', 'config_digest',
              'bootstrap_name', 'bootstrap_image', 'bootstrap_completion_path',
              'controller_image', 'docker_socket',
              'dev_policy', 'protected_policy', 'dev_journal', 'protected_journal',
              'roster_freeze_path', 'factory_commit_path', 'protected_close_path',
              'lifecycle_review_path',
              'deployment_manifest_path',
              'export_directory', 'journal_directory', 'deadline',
              'admin_input_volume', 'admin_input_subpath',
              'whole_round_manifest_digest', 'host_cost_path',
              'host_reserved_seconds', 'host_reserved_disk_bytes',
              'protected_close_step_digest', 'request_digest', 'digest'}
    if (type(value) is not dict or set(value) != fields
            or value['kind'] != 'FrozenNativeRoundHostLaunch'
            or value['digest'] != digest_jcs({k: v for k, v in value.items() if k != 'digest'})
            or not re.fullmatch(r'skillloop-bootstrap-[0-9a-f]{24}', value['bootstrap_name'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['bootstrap_image'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['controller_image'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['campaign_id'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['config_digest'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['whole_round_manifest_digest'])
            or type(value['host_reserved_seconds']) is not int
            or not 300<=value['host_reserved_seconds']<=1800
            or type(value['host_reserved_disk_bytes']) is not int
            or not 75497472<=value['host_reserved_disk_bytes']<=134217728
            or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', value[name])
                   for name in ('protected_close_step_digest', 'request_digest'))):
        raise ValueError('native_round_host_frozen_identity')
    for name in ('docker_socket', 'dev_policy', 'protected_policy',
                 'dev_journal', 'protected_journal', 'export_directory',
                 'journal_directory'):
        item = Path(value[name])
        if not item.is_absolute() or '..' in item.parts or str(item) != value[name]:
            raise ValueError('native_round_host_canonical_path')
    for name, suffix in (('roster_freeze_path', '/freeze.json'),
                         ('bootstrap_completion_path', '/pre-operator-complete.json'),
                         ('factory_commit_path', '/commit.json'),
                         ('protected_close_path', '.completed.json'),
                         ('lifecycle_review_path', '/completion.json'),
                         ('deployment_manifest_path', '/deployment.json'),
                         ('host_cost_path', '/pre-operator-host-cost.json')):
        item = Path(value[name])
        if (not item.is_absolute() or '..' in item.parts
                or str(item) != value[name] or not value[name].endswith(suffix)):
            raise ValueError('native_round_host_public_projection_path')
    subpath = value['admin_input_subpath']
    if (type(value['admin_input_volume']) is not str
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['admin_input_volume'])
            or type(subpath) is not str or subpath in {'', '.'}
            or PurePosixPath(subpath).is_absolute() or '..' in PurePosixPath(subpath).parts
            or str(PurePosixPath(subpath)) != subpath):
        raise ValueError('native_round_host_admin_original_destination')
    deadline = datetime.fromisoformat(value['deadline'].replace('Z', '+00:00'))
    if deadline.tzinfo is None or not 120 < deadline.timestamp() - time.time() <= 28800:
        raise ValueError('native_round_host_original_clock')
    value['_deadline'] = deadline.timestamp()
    return value


def _save(directory, name, value):
    value = dict(value)
    value['digest'] = digest_jcs(value)
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical_json_line(value))
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return value


def _controller_file(engine, launch, path, *, uid, limit):
    actual = engine.inspect(launch['controller_id'])
    if (actual.get('Id') != launch['controller_id']
            or actual.get('Image') != launch['controller_image']
            or actual.get('Config', {}).get('User') != '21001:21001'
            or actual.get('Config', {}).get('Labels', {}).get('skillloop.role') != 'controller'
            or actual.get('Config', {}).get('Labels', {}).get('skillloop.deployment_epoch') != launch['deployment_epoch']
            or actual.get('State', {}).get('Running') is not True):
        raise RuntimeError('native_round_host_original_controller_not_live')
    raw = engine.archive(launch['controller_id'], path, maximum_bytes=limit + 16384)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        if len(members) != 1:
            raise ValueError('native_round_host_exact_public_file')
        member = members[0]
        if (not member.isfile() or member.issym() or member.islnk()
                or Path(member.name).name != Path(path).name
                or member.uid != uid or member.gid != 21001
                or stat.S_IMODE(member.mode) != (0o600 if uid == 21001 else 0o640)
                or member.size > limit):
            raise PermissionError('native_round_host_public_projection_custody')
        source = archive.extractfile(member)
        if source is None:
            raise ValueError('native_round_host_public_file_missing')
        content = source.read(limit + 1)
        if len(content) != member.size:
            raise ValueError('native_round_host_public_file_changed')
    result = decode_json(content)
    if result.get('digest') != digest_jcs({k: v for k, v in result.items() if k != 'digest'}):
        raise ValueError('native_round_host_public_projection_seal')
    return result


def _resolve_original_controller(engine, launch):
    """Resolve the ID created by the original bootstrap, never a prefilled ID."""
    actual = engine.inspect(launch['bootstrap_name'])
    config = actual.get('Config', {})
    if (actual.get('Name') != '/' + launch['bootstrap_name']
            or actual.get('Image') != launch['bootstrap_image']
            or config.get('Labels', {}).get('skillloop.role') != 'bootstrap'
            or config.get('Labels', {}).get('skillloop.deployment_epoch') != launch['deployment_epoch']
            or actual.get('State', {}).get('Running') is not False
            or actual.get('State', {}).get('ExitCode') != 0):
        raise ValueError('native_round_host_original_bootstrap_identity')
    raw = engine.archive(actual['Id'], launch['bootstrap_completion_path'],
                         maximum_bytes=262144 + 16384)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        if len(members) != 1:
            raise ValueError('native_round_host_original_bootstrap_completion')
        member = members[0]
        if (not member.isfile() or member.issym() or member.islnk()
                or Path(member.name).name != 'pre-operator-complete.json'
                or (member.uid, member.gid, stat.S_IMODE(member.mode)) != (21001, 21001, 0o600)
                or member.size > 262144):
            raise PermissionError('native_round_host_original_bootstrap_custody')
        source = archive.extractfile(member)
        if source is None:
            raise ValueError('native_round_host_original_bootstrap_file_missing')
        content = source.read(262145)
        if len(content) != member.size:
            raise ValueError('native_round_host_original_bootstrap_file_changed')
    completion = decode_json(content)
    if (type(completion) is not dict
            or set(completion) != {'kind', 'launch_digest', 'deployment_digest', 'proxy_id',
                                  'controller_id', 'operator_socket', 'qualification_issued', 'digest'}
            or completion.get('digest') != digest_jcs({k: v for k, v in completion.items() if k != 'digest'})
            or completion['kind'] != 'PreOperatorBootstrapCompletion'
            or completion['qualification_issued'] is not False
            or not re.fullmatch(r'[0-9a-f]{64}', completion['controller_id'])):
        raise ValueError('native_round_host_original_bootstrap_seal')
    launch['controller_id'] = completion['controller_id']
    return completion


def _wait_for(engine, launch, name, *, uid, limit, expected_kind):
    path = launch[name]
    while time.time() < launch['_deadline'] - 120:
        try:
            result = _controller_file(engine, launch, path, uid=uid, limit=limit)
        except DockerEngineError as error:
            if error.status != 404:
                raise
            time.sleep(1)
            continue
        if result.get('kind') != expected_kind:
            raise ValueError('native_round_host_original_projection_kind')
        return result
    raise TimeoutError('native_round_host_original_projection_clock')


def _require_future_projection(engine, launch, name, *, uid, limit):
    try:
        _controller_file(engine, launch, launch[name], uid=uid, limit=limit)
    except DockerEngineError as error:
        if error.status == 404:
            return
        raise
    raise RuntimeError('native_round_host_phase_already_started_no_new_backend')


def _verify_admin_destination(engine, launch):
    manifest = _controller_file(engine, launch, launch['deployment_manifest_path'],
                                uid=21010, limit=2097152)
    if (manifest.get('kind') != 'FrozenWholeRoleDeployment'
            or manifest.get('campaign_digest') != launch['campaign_id']
            or manifest.get('deployment_epoch') != launch['deployment_epoch']
            or manifest.get('image') != launch['controller_image']
            or manifest.get('whole_round_manifest_digest') != launch['whole_round_manifest_digest']
            or manifest.get('volume') != launch['admin_input_volume']):
        raise ValueError('native_round_host_original_deployment_binding')
    recipes = [d['value'] for d in manifest['documents']
               if d['value'].get('kind') == 'FrozenNativeLifecycleImportProduction'
               and d['value'].get('campaign_id') == launch['campaign_id']]
    if len(recipes) != 1:
        raise ValueError('native_round_host_current_admin_recipe_required')
    recipe = recipes[0]
    admin = manifest['roles']['admin']
    module = 'skillloop.runtime.role_command_worker'
    config = (admin['config'] if admin['config']['Cmd'] == ['-m', module]
              else admin.get('entry_variants', {}).get(module, {}).get('config'))
    if config is None:
        raise ValueError('native_round_host_actual_admin_entry')
    target = PurePosixPath(recipe['input_directory'])
    matches = [m for m in config['HostConfig']['Mounts']
               if m.get('Type') == 'volume'
               and target.is_relative_to(PurePosixPath(m['Target']))]
    if not matches:
        raise ValueError('native_round_host_admin_input_unmounted')
    mount = max(matches, key=lambda m: len(PurePosixPath(m['Target']).parts))
    original = (PurePosixPath(mount['VolumeOptions']['Subpath']) /
                target.relative_to(PurePosixPath(mount['Target'])))
    declared = {d['path']: d for d in manifest['directories']}.get(str(original))
    if (mount.get('Source') != launch['admin_input_volume']
            or mount.get('ReadOnly') is not True
            or str(original) != launch['admin_input_subpath']
            or declared is None
            or (declared['uid'], declared['gid'], declared['mode']) != (21010, 21010, 0o700)
            or recipe.get('deployment_epoch') != launch['deployment_epoch']
            or recipe.get('deadline') != launch['deadline']):
        raise ValueError('native_round_host_original_admin_destination_mismatch')
    return manifest['digest']


def _verify_original_host_budget(engine, launch):
    cost = _controller_file(engine, launch, launch['host_cost_path'], uid=21001, limit=262144)
    expected = {'seconds': launch['host_reserved_seconds'], 'input_tokens': 0,
                'output_tokens': 0, 'disk_bytes': launch['host_reserved_disk_bytes']}
    spending = cost.get('spending')
    if (cost.get('kind') != 'PreOperatorNativeHostCost'
            or cost.get('native_host_launch_digest') != launch['digest']
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', cost.get('launch_digest', ''))
            or type(spending) is not dict
            or spending.get('operation_key') != 'native-host-' + launch['digest'][7:]
            or spending.get('stage') != 'private_factory_lifecycle'
            or spending.get('requested_cost') != expected):
        raise ValueError('native_round_host_original_whole_cost_required')
    return cost


def run(policy_path):
    launch = _read_policy(policy_path)
    journal = Path(launch['journal_directory'])
    _owned(journal, os.geteuid(), 0o700, directory=True)
    if any(journal.iterdir()):
        raise RuntimeError('native_round_host_existing_intent_requires_recovery')
    for name in ('dev_journal', 'protected_journal', 'export_directory'):
        directory = Path(launch[name])
        _owned(directory, os.geteuid(), 0o700, directory=True)
        if any(directory.iterdir()):
            raise RuntimeError('native_round_host_existing_original_requires_recovery')
    dev = NativeBackendSupervisor(policy_path=launch['dev_policy'], journal_directory=launch['dev_journal'])
    protected = NativeBackendSupervisor(policy_path=launch['protected_policy'], journal_directory=launch['protected_journal'])
    for manager, phase in ((dev, 'dev'), (protected, 'protected')):
        if (manager.policy['phase'] != phase
                or manager.policy['campaign_id'] != launch['campaign_id']
                or manager.policy['deployment_epoch'] != launch['deployment_epoch']
                or manager.policy['config_digest'] != launch['config_digest']
                or manager.policy['campaign_deadline'] != launch['deadline']):
            raise ValueError('native_round_host_backend_original_binding')
    startup_close_bound = (dev.policy['startup_seconds'] + dev.policy['stop_seconds']
        + protected.policy['startup_seconds'] + protected.policy['stop_seconds'] + 60 + 100)
    if startup_close_bound > launch['host_reserved_seconds']:
        raise ValueError('native_round_host_original_process_and_transfer_cost')
    engine = DockerEngine(launch['docker_socket'])
    bootstrap = _resolve_original_controller(engine, launch)
    deployment_digest = _verify_admin_destination(engine, launch)
    if bootstrap['deployment_digest'] != deployment_digest:
        raise ValueError('native_round_host_original_bootstrap_deployment')
    cost = _verify_original_host_budget(engine, launch)
    if bootstrap['launch_digest'] != cost['launch_digest']:
        raise ValueError('native_round_host_original_bootstrap_cost_identity')
    # Starting development after a roster freeze would create a convincing
    # but temporally false backend history. Fail before the first process or
    # spending effect if any later phase has already appeared.
    _require_future_projection(engine, launch, 'roster_freeze_path', uid=21005, limit=262144)
    _require_future_projection(engine, launch, 'factory_commit_path', uid=21004, limit=262144)
    _require_future_projection(engine, launch, 'lifecycle_review_path', uid=21005, limit=262144)
    _require_future_projection(engine, launch, 'protected_close_path', uid=21001, limit=262144)
    _save(journal, 'intent.json', {'kind': 'NativeRoundHostIntent',
        'launch_digest': launch['digest'], 'deployment_digest': deployment_digest,
        'budget_digest': cost['digest'], 'bootstrap_completion_digest': bootstrap['digest'],
        'controller_id': launch['controller_id'],
        'automatic_reexecution_allowed': False})
    dev.start()
    roster = _wait_for(engine, launch, 'roster_freeze_path', uid=21005, limit=262144,
                       expected_kind='FrozenCampaignSubjectRoster')
    if (roster.get('campaign_id') != launch['campaign_id']
            or roster.get('deployment_epoch') != launch['deployment_epoch']
            or roster.get('config_digest') != launch['config_digest']
            or roster.get('protected_evaluation') != 'not_started'):
        raise ValueError('native_round_host_original_roster_binding')
    _save(journal, 'roster-observed.json', {'kind': 'NativeRoundRosterObserved',
        'roster_digest': roster['digest'], 'controller_id': launch['controller_id']})
    dev.stop()
    factory = _wait_for(engine, launch, 'factory_commit_path', uid=21004, limit=262144,
                        expected_kind='FormalPrivateFactoryCommit')
    if (factory.get('campaign_public_ref') != launch['campaign_id']
            or factory.get('aggregate_status') != 'sealed'
            or not re.fullmatch(r'protected-[0-9a-f]{32}', factory.get('opaque_ref', ''))):
        raise ValueError('native_round_host_original_factory_binding')
    _save(journal, 'factory-observed.json', {'kind': 'NativeRoundFactoryObserved',
        'factory_digest': factory['digest'], 'opaque_ref': factory['opaque_ref']})
    protected.start()
    try:
        receipt = dev.export_lifecycle(protected=protected, opaque_ref=factory['opaque_ref'],
                                       output_directory=launch['export_directory'])
        _save(journal, 'exported.json', {'kind': 'NativeRoundHostExported',
            'export_digest': receipt['digest'], 'opaque_ref': factory['opaque_ref'],
            'qualification_issued': False})
        from skillloop.runtime.native_admin_transfer import transfer_original_export
        transferred = transfer_original_export(engine=engine, launch=launch, receipt=receipt, journal=journal)
        review = _wait_for(engine, launch, 'lifecycle_review_path', uid=21005, limit=262144,
                           expected_kind='OpaqueNativeLifecycleReviewCompletion')
        if (review.get('campaign_public_ref') != launch['campaign_id']
                or review.get('deployment_epoch') != launch['deployment_epoch']
                or review.get('aggregate_status') != 'reviewed'
                or review.get('qualification_issued') is not False):
            raise ValueError('native_round_host_original_independent_lifecycle_review')
        from skillloop.runtime.native_admin_transfer import retire_verified_transfer
        retire_verified_transfer(engine=engine, launch=launch, journal=journal,
            transfer=transferred, review_digest=review['digest'])
        # Remain the original parent and drain the protected backend through
        # the real private tasks. A process restart cannot reconstruct this
        # Popen or launch a second backend under the same original journal.
        close = _wait_for(engine, launch, 'protected_close_path', uid=21001, limit=262144,
                          expected_kind='CampaignStageCompleted')
        if (close.get('step_digest') != launch['protected_close_step_digest']
                or close.get('request_digest') != launch['request_digest']):
            raise ValueError('native_round_host_original_close_binding')
        stopped = protected.stop()
        return _save(journal, 'closed.json', {'kind': 'NativeRoundHostClosed',
            'export_digest': receipt['digest'], 'protected_stop_digest': stopped['digest'],
            'qualification_issued': False})
    except BaseException as error:
        try:
            _save(journal, 'failure.json', {'kind': 'NativeRoundHostFailure',
                'error_type': type(error).__name__, 'automatic_reexecution_allowed': False,
                'qualification_issued': False})
        except BaseException as custody_error:
            error.add_note('native_round_original_failure_custody:' + type(custody_error).__name__)
        if protected.process is not None and protected.process.poll() is None:
            try:
                protected.stop()
            except BaseException as close_error:
                error.add_note('native_round_original_backend_close:' + type(close_error).__name__)
        raise


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        raise SystemExit(64)
    run(sys.argv[1])
