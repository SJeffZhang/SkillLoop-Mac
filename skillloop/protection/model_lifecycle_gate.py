"""Gate reconstructs native lifecycle from Admin-custodied host raw records.

This reviews actual process observations; identity-only probes are rejected.
It does not certify an unobserved process or permit Controller private access.
"""
from datetime import datetime, timezone
import os
import hashlib
from pathlib import Path
import re
import stat

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.authority import ProtectionAuthority
from skillloop.protocol import canonical_json_line, digest_jcs


def _time(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None: raise ValueError('lifecycle_real_utc_required')
    return result.astimezone(timezone.utc)


def _sealed(value, kind):
    if (type(value) is not dict or value.get('kind') != kind
            or value.get('digest') != digest_jcs({k: v for k, v in value.items() if k != 'digest'})):
        raise ValueError('lifecycle_raw_record_identity')
    return value


def _start(raw, phase, record):
    if type(raw) is not dict or set(raw) != {'intent', 'created', 'started'}:
        raise ValueError('lifecycle_complete_start_records')
    intent = _sealed(raw['intent'], 'NativeBackendStartIntent')
    created = _sealed(raw['created'], 'NativeBackendProcessCreated')
    started = _sealed(raw['started'], 'NativeBackendStarted')
    policy = _sealed(intent['policy'], 'FrozenNativeHostBackend')
    if (any(row['policy_digest'] != policy['digest'] for row in (intent, created, started))
            or created['intent_digest'] != intent['digest'] or started['process'] != created
            or started['policy'] != policy or policy['phase'] != phase
            or any(policy[k] != record[k] for k in ('campaign_id', 'deployment_epoch', 'config_digest', 'source_index_digest'))
            or policy['campaign_deadline'] != record['deadline']
            or policy['tokenizer_hashes'] != record['config']['tokenizer_hashes']
            or policy['model_manifest_digest'] != record['config']['model_manifest_digest']
            or started.get('listener_pids') != [created['pid']]
            or started.get('no_inference_dispatched_by_startup') is not True
            or started['observed']['loaded'].get('models') != []
            or started['observed']['version'].get('version') != policy['backend_version']):
        raise ValueError('lifecycle_start_pins_or_cache')
    matches = [m for m in started['observed']['models']['models'] if m.get('name') == policy['model_id']]
    if len(matches) != 1 or 'sha256:' + matches[0]['digest'] != policy['model_manifest_digest']:
        raise ValueError('lifecycle_native_model_manifest')
    if (type(created['pid']) is not int or created['pid'] < 2 or created['pgid'] != created['pid']
            or not _time(intent['created_at']) <= _time(created['created_at']) <= _time(started['ready_at'])
            or (_time(started['ready_at']) - _time(intent['created_at'])).total_seconds() > policy['startup_seconds']):
        raise ValueError('lifecycle_start_actual_clock_and_process')
    roots = [p for p in started['process_inventory'] if p['pid'] == created['pid']]
    if len(roots) != 1 or roots[0]['pgid'] != created['pgid']:
        raise ValueError('lifecycle_start_process_inventory')
    return policy, created, started, roots[0]


def review_lifecycle(*, assignment_path, private_authority_directory, output_directory, gateway_output_directory=None, opaque_output_directory=None):
    if os.geteuid() != 21005 or 21004 not in set(os.getgroups()) | {os.getegid()}:
        raise PermissionError('lifecycle_independent_gate_actual_uid')
    job = read_owned(assignment_path, uid=21010, gid=21005, limit=8388608)
    if (set(job) != {'kind', 'campaign_id', 'opaque_ref', 'development', 'private', 'digest'}
            or job['kind'] != 'AdminNativeLifecycleEvidence'):
        raise ValueError('lifecycle_admin_evidence_shape')
    authority = ProtectionAuthority(Path(private_authority_directory), readonly=True)
    record = authority.resolve_formal_bundle(campaign=job['campaign_id'], opaque_ref=job['opaque_ref'])
    deadline = _time(record['deadline'])
    if (deadline - datetime.now(timezone.utc)).total_seconds() <= 120:
        raise TimeoutError('lifecycle_original_terminal_reserve')
    dev = job['development']
    if type(dev) is not dict or set(dev) != {'start', 'stop_intent', 'stopped'}:
        raise ValueError('lifecycle_development_stop_required')
    dp, dc, ds, dr = _start(dev['start'], 'dev', record)
    pp, pc, ps, pr = _start(job['private'], 'protected', record)
    si = _sealed(dev['stop_intent'], 'NativeBackendStopIntent')
    stopped = _sealed(dev['stopped'], 'NativeBackendStopped')
    if (si['policy_digest'] != dp['digest'] or stopped['policy_digest'] != dp['digest']
            or si['pid'] != dc['pid'] or stopped['pid'] != dc['pid']
            or stopped.get('process_group_absent') is not True
            or stopped.get('observed_descendants_absent') is not True
            or stopped.get('log_complete') is not True or stopped.get('log_overflow') is not False
            or stopped.get('log_error') is not None
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', stopped['backend_log_digest'])
            or si['owned_process_inventory'] != stopped['owned_process_inventory']):
        raise ValueError('lifecycle_development_closure_evidence')
    # Hash the preserved original log, rather than accepting its hash as a
    # caller assertion. The trusted Admin import grants Gate read-only custody.
    log_path = Path(assignment_path).parent / 'development-backend.log'
    fd = os.open(log_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != (21010, 21005, 0o640)
                or type(dp['maximum_log_bytes']) is not int
                or not 4096 <= dp['maximum_log_bytes'] <= 67108864
                or before.st_size > dp['maximum_log_bytes']):
            raise PermissionError('lifecycle_original_log_custody_capacity')
        log_hash = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''):
            if (deadline - datetime.now(timezone.utc)).total_seconds() <= 120:
                raise TimeoutError('lifecycle_original_log_review_clock')
            log_hash.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('lifecycle_original_log_changed')
    if 'sha256:' + log_hash.hexdigest() != stopped['backend_log_digest']:
        raise ValueError('lifecycle_original_log_digest')
    owned = si['owned_process_inventory']
    if (not any(p['pid'] == dc['pid'] and p['started'] == dr['started'] for p in owned)
            or any(p['pgid'] != dc['pgid'] for p in owned)
            or any(p['pid'] == old['pid'] and p['started'] == old['started']
                   for p in stopped['after_process_inventory'] for old in owned)):
        raise ValueError('lifecycle_development_processes_not_closed')
    stop_time = _time(stopped['stopped_at'])
    if (not _time(ds['ready_at']) <= _time(si['requested_at']) <= stop_time
            or (stop_time - _time(si['requested_at'])).total_seconds() > dp['stop_seconds']
            or stop_time >= _time(job['private']['intent']['created_at'])
            or _time(ps['ready_at']) >= deadline
            or (dc['pid'], dr['started']) == (pc['pid'], pr['started'])):
        raise ValueError('lifecycle_real_phase_order')
    pins = ('host_admin_uid', 'binary_digest', 'model_manifest_digest', 'model_files', 'tokenizer_hashes', 'model_id', 'backend_version')
    if any(dp[k] != pp[k] for k in pins):
        raise ValueError('lifecycle_phase_artifact_changed')
    value = {'kind': 'GatePrivateModelLifecycleReview',
        **{k: record[k] for k in ('campaign_id', 'deployment_epoch', 'config_digest', 'source_index_digest')},
        'factory_epoch_id': record['bundle']['epoch_id'], 'admin_evidence_digest': job['digest'],
        'development_stop_evidence_digest': stopped['digest'], 'private_start_evidence_digest': ps['digest'],
        'model_manifest_digest': pp['model_manifest_digest'], 'tokenizer_hashes': pp['tokenizer_hashes'],
        'development_backend_stopped': True, 'private_backend_fresh': True, 'isolation_verified': True,
        'gate_uid': 21005, 'review_completed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'qualification_issued': False, 'scope': 'dedicated_native_process_observed_lifecycle'}
    value['digest'] = digest_jcs(value)
    output = Path(output_directory); info = output.lstat()
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (21005, 21004, 0o750)):
        raise PermissionError('lifecycle_gate_private_output')
    fd = os.open(output / 'private-lifecycle.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), -1, 21004); os.fchmod(stream.fileno(), 0o640)
        stream.write(canonical_json_line(value)); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    if gateway_output_directory is not None:
        gateway_output = Path(gateway_output_directory); grant_info = gateway_output.lstat()
        if (not gateway_output.is_absolute() or gateway_output.is_symlink() or not stat.S_ISDIR(grant_info.st_mode)
                or (grant_info.st_uid, grant_info.st_gid, stat.S_IMODE(grant_info.st_mode)) != (21005, 21011, 0o750)):
            raise PermissionError('lifecycle_gateway_grant_custody')
        grant = {'kind': 'GateNativeBackendGrant', 'phase': 'protected',
            **{k: record[k] for k in ('campaign_id', 'deployment_epoch', 'config_digest', 'source_index_digest')},
            'campaign_deadline': record['deadline'], 'backend_version': pp['backend_version'],
            'model_id': pp['model_id'], 'model_manifest_digest': pp['model_manifest_digest'],
            'tokenizer_hashes': pp['tokenizer_hashes'], 'model_port': pp['port'],
            'host_process_pid': pc['pid'], 'host_process_started': pr['started'],
            'lifecycle_review_digest': value['digest'], 'gate_uid': 21005, 'qualification_issued': False}
        grant['digest'] = digest_jcs(grant)
        fd = os.open(gateway_output / 'backend-grant.json',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), -1, 21011); os.fchmod(stream.fileno(), 0o640)
            stream.write(canonical_json_line(grant)); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(gateway_output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    if opaque_output_directory is not None:
        from skillloop.protection.current_task import _directory,_publish
        # Controller receives no host PID, private evidence digest, Factory
        # seed, task plan, gateway grant or per-case result.
        projection=_directory(opaque_output_directory,21005,21001,0o750)
        completion={'kind':'OpaqueNativeLifecycleReviewCompletion',
            'campaign_public_ref':record['campaign_id'],'deployment_epoch':record['deployment_epoch'],
            'aggregate_status':'reviewed','qualification_issued':False}
        completion['digest']=digest_jcs(completion)
        _publish(projection/'completion.json',completion,21001)
    return value


def main():
    os.umask(0o077)
    review_lifecycle(assignment_path='/lifecycle/evidence.json',
        private_authority_directory='/private-authority', output_directory='/reviews',
        gateway_output_directory='/gateway-review',opaque_output_directory='/public-lifecycle')


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        import sys
        import traceback
        # Detailed private diagnostics belong to Gate/Evaluator custody only.
        try:
            output = Path('/reviews'); info = output.lstat()
            if (os.geteuid() == 21005 and not output.is_symlink()
                    and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (21005, 21004, 0o750)):
                value = {'kind': 'PrivateModelLifecycleReviewFailure', 'error_type': type(error).__name__,
                    'private_traceback': traceback.format_exc(), 'qualification_issued': False}
                value['digest'] = digest_jcs(value)
                fd = os.open(output / 'private-lifecycle.failure.json',
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(canonical_json_line(value)); stream.flush(); os.fsync(stream.fileno())
                fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(fd)
                finally: os.close(fd)
        except BaseException:
            pass  # Preserve stable external failure even when its private disk is full.
        sys.stderr.write('model_lifecycle_review_unavailable\n')
        raise SystemExit(1)
