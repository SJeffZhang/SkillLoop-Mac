"""Controller-side resource admission for a new, explicitly bound deployment.

The controller stages resource tasks in ReservedProxyStore beforehand. This
client uses its authenticated control socket and journals exact requests before
sending them. A single matrix controller owns the SpendingLedger. Unknown or
expired transport intents fail closed; no spent slot is restored or relaunched.
"""
from contextlib import contextmanager, closing
from datetime import datetime, timedelta, timezone
import fcntl
import os
from pathlib import Path
import sqlite3
import stat

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs, validate_envelope
from skillloop.proxy.wire import make_control, validate_control
from skillloop.runtime.client import ProxyClient, ProxyRPCError


class ControllerResourceAdmission:
    def __init__(self, plan, state_path, socket_dir):
        if os.geteuid() != 21001:
            raise PermissionError('resource_controller_uid_required')
        if plan['digest'] != digest_jcs({k: v for k, v in plan.items() if k != 'digest'}):
            raise ValueError('reservation_plan_digest')
        self.plan = decode_json(canonical_json_line(plan))
        self.path = Path(state_path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent=self.path.parent.lstat()
        if (self.path.parent.is_symlink() or parent.st_uid!=os.geteuid() or
                stat.S_IMODE(parent.st_mode)!=0o700 or self.path.is_symlink()):
            raise ValueError('reservation_state_symlink')
        if self.path.exists():
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 21001 or stat.S_IMODE(info.st_mode) != 0o600:
                raise PermissionError('reservation_state_file_owner')
        else:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        server_uid=plan.get('proxy_server_uid',21003)
        if type(server_uid) is not int or server_uid!=21003:
            raise ValueError('reservation_frozen_proxy_uid_required')
        # The controller authenticates the actual frozen Proxy before sending
        # its reserve/release intents or any private task identity.
        self.client = ProxyClient(socket_dir, timeout_seconds=5,expected_server_uid=server_uid)
        with self._locked(), closing(sqlite3.connect(self.path)) as db:
            os.chmod(self.path, 0o600)
            db.execute('PRAGMA synchronous=FULL')
            db.executescript('CREATE TABLE IF NOT EXISTS admission_policy(singleton INTEGER PRIMARY KEY,digest TEXT NOT NULL);'
                             'CREATE TABLE IF NOT EXISTS admissions(entry TEXT PRIMARY KEY,body TEXT NOT NULL);')
            row = db.execute('SELECT digest FROM admission_policy WHERE singleton=1').fetchone()
            if row and row[0] != self.plan['digest']:
                raise ValueError('reservation_plan_changed')
            db.execute('INSERT OR IGNORE INTO admission_policy VALUES(1,?)', (self.plan['digest'],))
            db.commit()

    @contextmanager
    def _locked(self):
        fd = os.open(str(self.path)+'.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 21001 or stat.S_IMODE(info.st_mode) != 0o600:
                raise PermissionError('reservation_lock_owner')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _read(self, digest):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT body FROM admissions WHERE entry=?', (digest,)).fetchone()
        if not row:
            return None
        value = decode_json(row[0].encode())
        if value['digest'] != digest_jcs({k: v for k, v in value.items() if k != 'digest'}):
            raise ValueError('reservation_state_digest')
        return value

    def _save(self, digest, state):
        state = {k: v for k, v in state.items() if k != 'digest'}
        state['digest'] = digest_jcs(state)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('INSERT OR REPLACE INTO admissions VALUES(?,?)', (digest, canonical_json_line(state).decode()))
            db.commit()
        fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return state

    def _binding(self, entry):
        digest = entry['digest']
        if digest != digest_jcs({k: v for k, v in entry.items() if k != 'digest'}):
            raise ValueError('reservation_entry_binding')
        binding = self.plan['entries'].get(digest)
        if (not binding or binding['entry_id'] != entry['entry_id'] or
                entry['source_index_digest'] != self.plan['source_digest'] or
                entry['config'].get('resource_admission_config') != self.plan['config_id']):
            raise ValueError('reservation_entry_binding')
        return digest, binding

    @staticmethod
    def _request(method, params, operation):
        return make_control('ControlRequest', {'operation_id': operation,
            'deadline': (datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00', 'Z'),
            'method': method, 'params': params})

    def _rpc(self, request):
        return self.client._send('control.sock', request)['result']

    @staticmethod
    def _live(request):
        deadline = datetime.fromisoformat(request['body']['deadline'].replace('Z', '+00:00'))
        if datetime.now(timezone.utc) >= deadline:
            raise ValueError('reservation_unknown_expired_intent')

    def reserve(self, entry):
        digest, binding = self._binding(entry)
        with self._locked():
            state = self._read(digest)
            if state and state['phase'] in ('released', 'cancelling'):
                raise ValueError('reservation_released_or_cancelling')
            if state and state['phase'] == 'reserved':
                expiry = datetime.fromisoformat(state['lease']['body']['expires_at'].replace('Z', '+00:00'))
                if datetime.now(timezone.utc) >= expiry:
                    raise ValueError('reservation_lease_expired')
                return state['lease']
            if state is None or state['phase'] == 'rejected':
                request = self._request('start_run', {k: binding[k] for k in ('run_request_digest', 'task_binding_digest')},
                                        'reserve-'+digest[7:39])
                state = self._save(digest, {'phase': 'reserving', 'request': request})
            self._live(state['request'])
            try:
                lease = self._rpc(state['request'])
            except ProxyRPCError as error:
                # These replies are produced before the start_run commit.
                if str(error) in ('queue_full', 'storage_floor'):
                    state.update(phase='rejected', rejection=str(error))
                    self._save(digest, state)
                raise
            validate_envelope(lease)
            if (lease['kind'] != 'Lease' or lease['body']['run_id'] != binding['run_id'] or
                    lease['body']['campaign_id'] != binding['campaign_id'] or
                    lease['body']['fencing_token'] != 1 or lease['body']['state'] != 'active' or
                    datetime.fromisoformat(lease['body']['expires_at'].replace('Z', '+00:00')) <= datetime.now(timezone.utc)):
                raise ValueError('reservation_lease_binding')
            state.update(phase='reserved', lease=lease)
            self._save(digest, state)
            return lease

    def release(self, entry):
        digest, binding = self._binding(entry)
        with self._locked():
            state = self._read(digest)
            if state is None:
                return None  # A retained old slot has no new reservation.
            if state['phase'] == 'released':
                return state['cancellation']
            if state['phase'] not in ('reserved', 'cancelling'):
                raise ValueError('reservation_release_unknown')
            if state['phase'] == 'reserved':
                state.update(phase='cancelling', cancel_request=self._request('cancel_run',
                    {'run_id': binding['run_id'], 'expected_fence': state['lease']['body']['fencing_token'],
                     'reason': 'controller has not launched a worker or has verified completed export'},
                    'release-'+digest[7:39]))
                state = self._save(digest, state)
            self._live(state['cancel_request'])
            cancellation = self._rpc(state['cancel_request'])
            validate_control(cancellation)
            if (cancellation['kind'] != 'CancellationResult' or
                    cancellation['body']['run_id'] != binding['run_id'] or
                    cancellation['body']['campaign_public_ref'] != binding['campaign_id'] or
                    cancellation['body']['effective_fence'] != state['lease']['body']['fencing_token']+1):
                raise ValueError('reservation_cancel_binding')
            state.update(phase='released', cancellation=cancellation)
            self._save(digest, state)
            return cancellation
