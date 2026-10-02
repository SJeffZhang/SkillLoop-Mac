"""Retire a caller-owned, inactive experiment evidence copy after verified export.

This is a local experiment adapter, not a production qualification authority.
The caller authenticates the closed chain and freezes its independent inventory
before use. The private activity directory and inactive copy require exclusive
ownership and no active writers. Original evidence and GitHub are not accessed.
"""
from contextlib import contextmanager
import io
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tarfile

from skillloop.protocol import decode_json, digest_bytes, digest_jcs, canonical_json_line


class ClosedExperimentArchive:
    MAX_BYTES = 64 * 1024 * 1024
    MAX_FILES = 2048

    def __init__(self, root, inventory, binding, *, config, fault_hook=None):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or not self.root.is_dir() or self.root.stat().st_mode & 0o077:
            raise ValueError('unsafe_activity_directory')
        if not config or not 0 < len(inventory) <= self.MAX_FILES:
            raise ValueError('unsafe_inventory')
        for name, item in inventory.items():
            path = PurePosixPath(name)
            if (path.is_absolute() or str(path) != name or '..' in path.parts or
                    '\\' in name or '\x00' in name or not path.parts or
                    set(item) != {'digest', 'bytes'} or
                    type(item['bytes']) is not int or item['bytes'] < 0 or
                    not re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest'])):
                raise ValueError('unsafe_inventory')
        if sum(v['bytes'] for v in inventory.values()) > self.MAX_BYTES:
            raise ValueError('archive_size_limit')
        if set(binding) != {'project', 'head', 'config', 'generation', 'campaign', 'receipt_digest'}:
            raise ValueError('receipt_binding')
        # Canonical round trip prevents subsequent caller mutation of the pins.
        self.inventory = decode_json(canonical_json_line(inventory))
        self.binding = decode_json(canonical_json_line(binding))
        self.policy = digest_jcs({'config': config, 'inventory': self.inventory, 'binding': self.binding})
        self.capsule = self.root / 'inactive-evidence'
        self.quarantine = self.root / 'retiring-evidence'
        self.archive = self.root / 'evidence.tar'
        self.registry = self.root / 'registry.sqlite'
        if self.registry.is_symlink() or not self.registry.is_file():
            raise ValueError('unsafe_registry')
        self.fault_hook = fault_hook or (lambda phase: None)
        with self._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS evidence_archives(campaign TEXT PRIMARY KEY,body TEXT NOT NULL)')

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.registry)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _load(self, db):
        row = db.execute('SELECT body FROM evidence_archives WHERE campaign=?', (self.binding['campaign'],)).fetchone()
        if not row:
            raise ValueError('withdrawal_required')
        body = decode_json(row[0].encode())
        sealed = dict(body)
        digest = sealed.pop('digest')
        if digest_jcs(sealed) != digest or body['policy_digest'] != self.policy:
            raise ValueError('archive_policy_binding')
        current = db.execute('SELECT generation,head,config FROM projects WHERE project=?', (self.binding['project'],)).fetchone()
        if current != (body['generation'], self.binding['head'], self.binding['config']):
            raise ValueError('archive_generation')
        return body

    def _save(self, db, body):
        body = {k: v for k, v in body.items() if k != 'digest'}
        body['digest'] = digest_jcs(body)
        db.execute('INSERT OR REPLACE INTO evidence_archives VALUES(?,?)',
                   (self.binding['campaign'], canonical_json_line(body).decode()))
        return body

    @staticmethod
    def _sync_directory(path):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _files(self, root, *, partial=False):
        if root.is_symlink() or not root.is_dir():
            raise ValueError('unsafe_evidence')
        found = {}
        for path in root.rglob('*'):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError('unsafe_evidence')
            if path.is_dir():
                continue
            name = path.relative_to(root).as_posix()
            pin = self.inventory.get(name)
            if pin is None or path.stat().st_size != pin['bytes']:
                raise ValueError('inventory_mismatch')
            flags = os.O_RDONLY | os.O_NOFOLLOW
            fd = os.open(path, flags)
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(pin['bytes'] + 1)
            found[name] = {'digest': digest_bytes(raw), 'bytes': len(raw)}
            if found[name] != pin:
                raise ValueError('inventory_mismatch')
        if not partial and found != self.inventory:
            raise ValueError('inventory_mismatch')
        return found

    def withdraw(self):
        with self._transaction() as db:
            if db.execute('SELECT 1 FROM evidence_archives WHERE campaign=?', (self.binding['campaign'],)).fetchone():
                return self._load(db)
            self._files(self.capsule)
            b = self.binding
            current = db.execute('SELECT generation,head,config FROM projects WHERE project=?', (b['project'],)).fetchone()
            row = db.execute('SELECT r.digest,r.body FROM receipts r JOIN triggers t ON r.campaign=t.campaign '
                             'WHERE r.campaign=? AND t.project=? AND t.generation=?',
                             (b['campaign'], b['project'], b['generation'])).fetchone()
            if (current != (b['generation'], b['head'], b['config']) or row is None or
                    row[0] != b['receipt_digest'] or digest_jcs(decode_json(row[1].encode())) != row[0]):
                raise ValueError('receipt_binding')
            decision = decode_json(row[1].encode())
            if (decision.get('production_ready') is not False or decision.get('verdict') != 'pass' or
                    not decision.get('scope', '').startswith('local_authority_exact_pr_')):
                raise ValueError('closed_experiment_scope_required')
            generation = b['generation'] + 1
            db.execute('UPDATE projects SET generation=? WHERE project=?', (generation, b['project']))
            return self._save(db, {'kind': 'ClosedExperimentArchive', 'policy_digest': self.policy,
                                  'receipt_digest': b['receipt_digest'], 'generation': generation,
                                  'state': 'withdrawn', 'eligibility': 'withdrawn', 'production_ready': False})

    def _verify_archive(self, expected_digest=None):
        if self.archive.is_symlink() or not self.archive.is_file():
            raise ValueError('unsafe_archive')
        if self.archive.stat().st_size > self.MAX_BYTES + self.MAX_FILES * 2048:
            raise ValueError('archive_size_limit')
        archive_digest = digest_bytes(self.archive.read_bytes())
        if expected_digest is not None and archive_digest != expected_digest:
            raise ValueError('archive_digest')
        found = {}
        with tarfile.open(self.archive, 'r:') as tar:
            for member in tar:
                pin = self.inventory.get(member.name)
                if not member.isfile() or member.name in found or pin is None or member.size != pin['bytes']:
                    raise ValueError('archive_content')
                with tar.extractfile(member) as stream:
                    raw = stream.read(member.size + 1)
                found[member.name] = {'digest': digest_bytes(raw), 'bytes': len(raw)}
        if found != self.inventory:
            raise ValueError('archive_content')
        return archive_digest

    def export(self):
        with self._transaction() as db:
            body = self._load(db)
            if body['state'] != 'withdrawn':
                self._verify_archive(body['archive_digest'])
                return body
            self._files(self.capsule)
            # An interrupted export remains present; it is verified, never overwritten.
            if not self.archive.exists() and not self.archive.is_symlink():
                with self.archive.open('xb') as output:
                    with tarfile.open(fileobj=output, mode='w:') as tar:
                        for name, pin in sorted(self.inventory.items()):
                            raw = (self.capsule / name).read_bytes()
                            if len(raw) != pin['bytes'] or digest_bytes(raw) != pin['digest']:
                                raise ValueError('inventory_mismatch')
                            info = tarfile.TarInfo(name)
                            info.size = len(raw)
                            info.mode = 0o600
                            tar.addfile(info, io.BytesIO(raw))
                    output.flush()
                    os.fsync(output.fileno())
                self._sync_directory(self.root)
            archive_digest = self._verify_archive()
            self._files(self.capsule)
            body.update(state='export_verified', archive_digest=archive_digest)
            return self._save(db, body)

    def retire(self):
        with self._transaction() as db:
            body = self._load(db)
            if body['state'] == 'withdrawn':
                raise ValueError('verified_export_required')
            self._verify_archive(body['archive_digest'])
            if body['state'] == 'retired':
                if self.capsule.exists() or self.quarantine.exists():
                    raise ValueError('ambiguous_evidence_directory')
                return body
            if body['state'] == 'retiring' and self.capsule.exists():
                raise ValueError('ambiguous_evidence_directory')
            if body['state'] == 'export_verified':
                if self.capsule.exists() and self.quarantine.exists():
                    raise ValueError('ambiguous_evidence_directory')
                source = self.capsule if self.capsule.exists() else self.quarantine
                self._files(source)
                if source == self.capsule:
                    self.capsule.rename(self.quarantine)
                    self._sync_directory(self.root)
                self._files(self.quarantine)
                body['state'] = 'retiring'
                self._save(db, body)
        self.fault_hook('before_remove')
        with self._transaction() as db:
            body = self._load(db)
            self._verify_archive(body['archive_digest'])
            if self.capsule.exists():
                raise ValueError('ambiguous_evidence_directory')
            if self.quarantine.exists():
                remaining = self._files(self.quarantine, partial=True)
                for name in remaining:
                    (self.quarantine / name).unlink()
                    self.fault_hook('file_removed')
                for path in sorted(self.quarantine.rglob('*'), key=lambda p: len(p.parts), reverse=True):
                    path.rmdir()
                self.quarantine.rmdir()
                self._sync_directory(self.root)
            body['state'] = 'retired'
            return self._save(db, body)
