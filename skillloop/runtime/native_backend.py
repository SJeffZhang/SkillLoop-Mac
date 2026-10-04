"""Trusted host administrator manages one dedicated native Ollama process.

No existing backend is stopped. Process creation/timeout ambiguity is retained
in its original journal; a restart of this manager does not launch a replacement.
Host records need the administrator's role-custody import before Linux Gate use.
"""
from datetime import datetime, timezone
import hashlib
import http.client
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import time
import threading

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs


def _stamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _owned(path, uid, mode, *, directory=False):
    info = path.lstat()
    if (path.is_symlink() or not path.is_absolute() or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != mode
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise PermissionError('native_backend_host_custody')
    return info


def _digest(path, deadline):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PermissionError('native_backend_artifact_regular_file')
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''):
            if time.time() >= deadline: raise TimeoutError('native_backend_original_clock')
            result.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('native_backend_artifact_changed')
    return 'sha256:' + result.hexdigest()


class NativeBackendSupervisor:
    def __init__(self, *, policy_path, journal_directory):
        uid = os.geteuid()
        policy_path, self.directory = Path(policy_path), Path(journal_directory)
        _owned(policy_path.parent, uid, 0o700, directory=True)
        info = _owned(policy_path, uid, 0o600)
        if info.st_size > 262144: raise ValueError('native_backend_host_policy_capacity')
        fd = os.open(policy_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream: self.policy = decode_json(stream.read(262145))
        p = self.policy
        fields = {'kind', 'host_admin_uid', 'campaign_id', 'deployment_epoch', 'config_digest',
            'source_index_digest', 'phase', 'campaign_deadline', 'startup_seconds', 'stop_seconds',
            'binary', 'binary_digest', 'models_directory', 'model_files', 'backend_version',
            'model_id', 'model_manifest_digest', 'tokenizer_hashes', 'port', 'maximum_log_bytes', 'digest'}
        if (set(p) != fields or p['kind'] != 'FrozenNativeHostBackend'
                or p['digest'] != digest_jcs({k: v for k, v in p.items() if k != 'digest'})
                or type(p['host_admin_uid']) is not int or p['host_admin_uid'] != uid
                or p['phase'] not in {'dev', 'protected'}
                or type(p['port']) is not int or not 1024 <= p['port'] <= 65535
                or any(type(p[k]) is not int or not 1 <= p[k] <= 300 for k in ('startup_seconds', 'stop_seconds'))
                or type(p['model_files']) is not dict or not 1 <= len(p['model_files']) <= 64
                or type(p['maximum_log_bytes']) is not int or not 4096 <= p['maximum_log_bytes'] <= 67108864
                or not p['tokenizer_hashes']):
            raise ValueError('native_backend_frozen_host_policy')
        for name in ('campaign_id', 'config_digest', 'source_index_digest', 'binary_digest', 'model_manifest_digest'):
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', p[name]):
                raise ValueError('native_backend_complete_identity')
        self.deadline = datetime.fromisoformat(p['campaign_deadline'].replace('Z', '+00:00'))
        if self.deadline.tzinfo is None or not 0 < self.deadline.timestamp() - time.time() <= 28800:
            raise ValueError('native_backend_original_campaign_clock')
        _owned(self.directory, uid, 0o700, directory=True)
        if any(self.directory.iterdir()):
            raise RuntimeError('native_backend_existing_intent_requires_recovery')
        self.process = None; self.log = None
        self.log_overflow = False; self.log_error = None; self.log_thread = None

    def _save(self, name, value):
        value = {'kind': name, 'policy_digest': self.policy['digest'], **value}
        value['digest'] = digest_jcs(value)
        fd = os.open(self.directory / (name + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical_json_line(value)); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        return value

    def _identity(self):
        output = {}
        for key, path in (('version', '/api/version'), ('models', '/api/tags'), ('loaded', '/api/ps')):
            connection = http.client.HTTPConnection('127.0.0.1', self.policy['port'], timeout=2)
            try:
                connection.request('GET', path); response = connection.getresponse()
                raw = response.read(1048577)
                if response.status != 200 or len(raw) > 1048576:
                    raise ValueError('native_backend_identity_response')
                output[key] = decode_json(raw)
            finally: connection.close()
        if output['version'].get('version') != self.policy['backend_version']:
            raise ValueError('native_backend_version_changed')
        models = [m for m in output['models']['models'] if m.get('name') == self.policy['model_id']]
        if len(models) != 1 or 'sha256:' + models[0]['digest'] != self.policy['model_manifest_digest']:
            raise ValueError('native_backend_manifest_changed')
        if output['loaded'].get('models') != []:
            raise ValueError('native_backend_startup_cache_not_empty')
        return output

    def _process_inventory(self, deadline):
        remaining = deadline - time.time()
        if remaining <= 0: raise TimeoutError('native_backend_process_audit_clock')
        result = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,lstart='],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=min(5, remaining), check=True, env={'PATH': '/usr/bin:/bin'})
        if len(result.stdout) > 1048576 or len(result.stderr) > 65536:
            raise ValueError('native_backend_process_inventory_capacity')
        rows = []
        for line in result.stdout.decode('ascii', 'strict').splitlines():
            parts = line.split(maxsplit=3)
            if len(parts) != 4: raise ValueError('native_backend_process_inventory_shape')
            rows.append({'pid': int(parts[0]), 'ppid': int(parts[1]),
                         'pgid': int(parts[2]), 'started': parts[3]})
        return rows

    def _listener_pids(self, deadline):
        remaining = deadline - time.time()
        if remaining <= 0: raise TimeoutError('native_backend_listener_audit_clock')
        result = subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP:' + str(self.policy['port']),
            '-sTCP:LISTEN', '-Fp'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=min(5, remaining), check=True,
            env={'PATH': '/usr/bin:/bin:/usr/sbin'})
        if len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise ValueError('native_backend_listener_capacity')
        rows = result.stdout.decode('ascii', 'strict').splitlines()
        pids = sorted({int(row[1:]) for row in rows if row.startswith('p')})
        if pids != [self.process.pid]:
            raise ValueError('native_backend_listener_not_owned_process')
        return pids

    def _drain_log(self):
        written = 0
        try:
            while True:
                block = self.process.stdout.read(65536)
                if not block: break
                remaining = self.policy['maximum_log_bytes'] - written
                if len(block) > remaining: self.log_overflow = True
                if remaining > 0:
                    data = block[:remaining]; self.log.write(data); self.log.flush()
                    os.fsync(self.log.fileno()); written += len(data)
                # Drain after the cap to avoid a blocked backend, while preserving
                # the overflow fact. Such a lifecycle is never reviewable as complete.
        except BaseException as error:
            self.log_error = type(error).__name__
        finally:
            self.process.stdout.close()

    def assert_live(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('native_backend_not_alive')
        if self.log_overflow or self.log_error:
            raise RuntimeError('native_backend_log_incomplete')

    def start(self):
        p = self.policy
        if self.process is not None: raise RuntimeError('native_backend_already_started')
        startup_end = min(time.time() + p['startup_seconds'], self.deadline.timestamp() - p['stop_seconds'] - 120)
        if startup_end <= time.time(): raise TimeoutError('native_backend_original_terminal_reserve')
        binary = Path(p['binary']); models = Path(p['models_directory'])
        if not binary.is_absolute() or binary.is_symlink() or not models.is_absolute() or models.is_symlink():
            raise PermissionError('native_backend_pinned_paths')
        if _digest(binary, startup_end) != p['binary_digest']:
            raise ValueError('native_backend_binary_changed')
        for name, expected in p['model_files'].items():
            parts = Path(name)
            if (parts.is_absolute() or '..' in parts.parts or not parts.parts or str(parts) != name
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected)):
                raise ValueError('native_backend_model_inventory')
            ancestor = models
            for part in parts.parts[:-1]:
                ancestor = ancestor / part
                if ancestor.is_symlink() or not ancestor.is_dir():
                    raise PermissionError('native_backend_model_parent_symlink')
            if _digest(models / name, startup_end) != expected:
                raise ValueError('native_backend_model_bytes_changed')
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(('127.0.0.1', p['port'])) == 0:
                raise RuntimeError('native_backend_port_owned_by_another_process')
        home = self.directory / 'home'
        home.mkdir(mode=0o700)
        intent = self._save('NativeBackendStartIntent', {'policy': p, 'created_at': _stamp(),
            'automatic_reexecution_allowed': False})
        fd = os.open(self.directory / 'backend.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.log = os.fdopen(fd, 'wb')
        env = {'HOME': str(home), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'OLLAMA_HOST': '127.0.0.1:' + str(p['port']),
            'OLLAMA_MODELS': str(models), 'OLLAMA_NUM_PARALLEL': '1', 'OLLAMA_MAX_LOADED_MODELS': '1',
            'OLLAMA_MAX_QUEUE': '1'}
        try:
            self.process = subprocess.Popen([str(binary), 'serve'], env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
            self.log_thread = threading.Thread(target=self._drain_log, daemon=True)
            self.log_thread.start()
            created = self._save('NativeBackendProcessCreated', {'intent_digest': intent['digest'],
                'pid': self.process.pid, 'pgid': os.getpgid(self.process.pid), 'created_at': _stamp()})
            while time.time() < startup_end:
                self.assert_live()
                try: observed = self._identity()
                except (OSError, http.client.HTTPException):
                    time.sleep(min(0.2, max(0, startup_end - time.time()))); continue
                return self._save('NativeBackendStarted', {'policy': p, 'process': created,
                    'observed': observed, 'ready_at': _stamp(),
                    'process_inventory': self._process_inventory(startup_end),
                    'listener_pids': self._listener_pids(startup_end),
                    'no_inference_dispatched_by_startup': True})
            raise TimeoutError('native_backend_startup_expired')
        except BaseException as error:
            try:
                if self.process is None:
                    self.log.close()
                else:
                    self.stop()
            except BaseException as secondary: error.add_note('native_backend_close_error:' + type(secondary).__name__)
            raise

    def stop(self):
        if self.process is None: raise RuntimeError('native_backend_creation_unknown_no_pid_recovery')
        end = min(time.time() + self.policy['stop_seconds'], self.deadline.timestamp())
        before = self._process_inventory(end)
        owned = {self.process.pid}
        while True:
            expanded = owned | {row['pid'] for row in before if row['ppid'] in owned}
            if expanded == owned: break
            owned = expanded
        descendants = [row for row in before if row['pid'] in owned or row['pgid'] == self.process.pid]
        self._save('NativeBackendStopIntent', {'pid': self.process.pid, 'requested_at': _stamp(),
            'owned_process_inventory': descendants})
        # The supervisor owns this new process group; never signal a discovered
        # foreign server or blindly kill a PID read from an old journal.
        try: os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        remaining = end - time.time()
        if remaining <= 0: raise TimeoutError('native_backend_original_close_clock')
        code = self.process.wait(timeout=remaining)
        try: os.killpg(self.process.pid, 0)
        except ProcessLookupError: group_absent = True
        else: group_absent = False
        if not group_absent: raise RuntimeError('native_backend_descendants_still_alive')
        after = self._process_inventory(end)
        escaped = [row for row in descendants if row['pgid'] != self.process.pid]
        survivors = [row for row in after if any(row['pid'] == old['pid'] and row['started'] == old['started']
                     for old in descendants)]
        if escaped or survivors:
            self._save('NativeBackendStopIncomplete', {'escaped': escaped, 'survivors': survivors,
                'observed_at': _stamp()})
            raise RuntimeError('native_backend_process_tree_not_closed')
        self.log_thread.join(timeout=max(0, end - time.time()))
        if self.log_thread.is_alive(): raise TimeoutError('native_backend_log_drain_unknown')
        self.log.flush(); os.fsync(self.log.fileno()); self.log.close()
        return self._save('NativeBackendStopped', {'pid': self.process.pid, 'returncode': code,
            'process_group_absent': True, 'observed_descendants_absent': True,
            'owned_process_inventory': descendants, 'after_process_inventory': after,
            'log_complete': not self.log_overflow and self.log_error is None,
            'log_overflow': self.log_overflow, 'log_error': self.log_error, 'stopped_at': _stamp(),
            'backend_log_digest': _digest(self.directory / 'backend.log', end)})
