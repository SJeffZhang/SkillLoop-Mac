"""Linux physical reservation gate for a separately configured proxy deployment.

The trusted proxy owns the database and reservation directory. This adapter
adds admission to the existing run transaction; it is not a qualification or
an API4 StorageReservation envelope. Evidence archive policy is separate.
"""
from contextlib import contextmanager, closing
import os
import sqlite3
import stat
from pathlib import Path

from skillloop.protocol import digest_jcs
from skillloop.proxy.store import ProxyError, ProxyStore


class ReservedProxyStore(ProxyStore):
    def __init__(self, path, *, deployment_epoch, queue_capacity,
                 reservation_bytes, free_floor_bytes, registry=None):
        if not hasattr(os, 'posix_fallocate'):
            raise RuntimeError('linux_physical_reservation_required')
        values = (queue_capacity, reservation_bytes, free_floor_bytes)
        if any(type(x) is not int for x in values) or not 1 <= queue_capacity <= 16:
            raise ValueError('reservation_policy_invalid')
        if (not 0 < reservation_bytes <= 8 * 1024 * 1024 or
                not 4096 <= free_floor_bytes <= (1 << 53)-1):
            raise ValueError('reservation_policy_invalid')
        self.queue_capacity = queue_capacity
        self.reservation_bytes = reservation_bytes
        self.free_floor_bytes = free_floor_bytes
        self.reservation_directory = Path(path).with_name(Path(path).name+'.reservations')
        if self.reservation_directory.is_symlink():
            raise ProxyError('reservation_directory_invalid')
        self.reservation_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.reservation_directory, 0o700)
        super().__init__(path, deployment_epoch=deployment_epoch, registry=registry)
        self.policy_digest = digest_jcs([deployment_epoch, queue_capacity,
                                        reservation_bytes, free_floor_bytes])
        with super()._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS reservation_policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL) STRICT')
            db.execute("CREATE TABLE IF NOT EXISTS storage_reservations (run_id TEXT PRIMARY KEY REFERENCES runs(run_id), filename TEXT UNIQUE NOT NULL, bytes INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('held','released'))) STRICT")
            previous = db.execute('SELECT digest FROM reservation_policy WHERE singleton=1').fetchone()
            if previous and previous[0] != self.policy_digest:
                raise ProxyError('reservation_policy_mismatch')
            db.execute('INSERT OR IGNORE INTO reservation_policy VALUES(1,?)', (self.policy_digest,))
            if db.execute("SELECT 1 FROM runs r LEFT JOIN storage_reservations s USING(run_id) WHERE r.state!='cancelled' AND (s.run_id IS NULL OR s.state!='held') LIMIT 1").fetchone():
                raise ProxyError('unreserved_existing_run')
            db.execute("UPDATE storage_reservations SET state='released' WHERE run_id IN (SELECT run_id FROM runs WHERE state='cancelled')")
            self._verify_held(db)
            held = {x[0] for x in db.execute("SELECT filename FROM storage_reservations WHERE state='held'")}
            # Writer lock prevents cleanup racing another process's allocation.
            for path in self.reservation_directory.glob('*.reserve'):
                if path.name not in held:
                    path.unlink()
            self._sync_directory()

    def _filename(self, run_id):
        return digest_jcs([self.deployment_epoch, run_id]).split(':')[1]+'.reserve'

    def _sync_directory(self):
        fd = os.open(self.reservation_directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def _verify_held(self, db):
        for row in db.execute("SELECT run_id,filename,bytes FROM storage_reservations WHERE state='held'"):
            if row['filename'] != self._filename(row['run_id']) or row['bytes'] != self.reservation_bytes:
                raise ProxyError('reservation_binding_mismatch')
            try: data = (self.reservation_directory/row['filename']).lstat()
            except FileNotFoundError: raise ProxyError('reservation_evidence_missing') from None
            if not stat.S_ISREG(data.st_mode) or data.st_size != row['bytes'] or data.st_blocks*512 < row['bytes']:
                raise ProxyError('reservation_evidence_missing')

    def _allocate(self, filename):
        fs = os.statvfs(self.reservation_directory)
        if fs.f_bavail*fs.f_frsize < self.free_floor_bytes+self.reservation_bytes:
            raise ProxyError('storage_floor')
        path = self.reservation_directory/filename
        fd = None
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.posix_fallocate(fd, 0, self.reservation_bytes)
            os.fsync(fd)
            self._sync_directory()
        except OSError as error:
            if fd is not None:
                path.unlink(missing_ok=True)
                self._sync_directory()
            raise ProxyError('storage_reservation_failed') from error
        finally:
            if fd is not None: os.close(fd)

    @contextmanager
    def _transaction(self):
        created, released = [], []
        try:
            with super()._transaction() as db:
                if db.execute("SELECT 1 FROM runs r LEFT JOIN storage_reservations s USING(run_id) WHERE r.state!='cancelled' AND (s.run_id IS NULL OR s.state!='held') LIMIT 1").fetchone():
                    raise ProxyError('unreserved_existing_run')
                yield db
                released = [x[0] for x in db.execute("SELECT s.filename FROM storage_reservations s JOIN runs r USING(run_id) WHERE s.state='held' AND r.state='cancelled'")]
                db.execute("UPDATE storage_reservations SET state='released' WHERE run_id IN (SELECT run_id FROM runs WHERE state='cancelled')")
                self._verify_held(db)
                pending = list(db.execute("SELECT r.run_id FROM runs r LEFT JOIN storage_reservations s USING(run_id) WHERE r.state!='cancelled' AND s.run_id IS NULL"))
                for row in pending:
                    if db.execute("SELECT count(*) FROM storage_reservations WHERE state='held'").fetchone()[0] >= self.queue_capacity:
                        raise ProxyError('queue_full')
                    filename = self._filename(row['run_id'])
                    self._allocate(filename)
                    created.append(filename)
                    db.execute("INSERT INTO storage_reservations VALUES(?,?,?,'held')", (row['run_id'], filename, self.reservation_bytes))
        except BaseException:
            # A lost ACK can raise after COMMIT. Never delete committed space.
            try:
                with closing(self._connect()) as db:
                    held = {x[0] for x in db.execute("SELECT filename FROM storage_reservations WHERE state='held'")}
                for filename in created+released:
                    if filename not in held:
                        (self.reservation_directory/filename).unlink(missing_ok=True)
                self._sync_directory()
            except (OSError, sqlite3.Error):
                # Unknown database state preserves allocations; restart reconciles.
                pass
            raise
        else:
            for filename in released:
                (self.reservation_directory/filename).unlink(missing_ok=True)
            if released: self._sync_directory()
