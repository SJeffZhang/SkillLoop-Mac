"""Trusted per-entry bounded filesystem keeper for native Mac dispatch.

A readonly container keeps the named tmpfs mounted until a stopped controller's
export and consistent backup are verified. Unknown workers/exports keep that
mount. The caller owns Docker access, authenticates the manifest and runs the
independent behavioral/API4 gate; this class grants no model qualification.
"""
from contextlib import contextmanager, closing
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs


class EvidenceQuotaKeeper:
    def __init__(self, plan, state_directory):
        if plan.get('digest') != digest_jcs({k: v for k, v in plan.items() if k != 'digest'}):
            raise ValueError('evidence_plan_seal')
        p = plan.get('policy', {})
        if (set(p) != {'config_id', 'quota_bytes', 'image', 'worker_source_digest',
                       'deployment_epoch', 'keeper_module_digest'} or
                type(p['quota_bytes']) is not int or not 4096 <= p['quota_bytes'] <= 536870912 or
                p['keeper_module_digest'] != digest_bytes(Path(__file__).read_bytes()) or
                not plan.get('entries') or not plan.get('manifest_digest')):
            raise ValueError('evidence_quota_policy')
        self.plan = decode_json(canonical_json_line(plan))
        self.policy = self.plan['policy']
        self.root = Path(state_directory).absolute()
        if self.root.is_symlink():
            raise ValueError('evidence_state_directory')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.stat().st_mode & 0o077:
            raise ValueError('evidence_state_directory')
        self.journal = self.root/'keeper.sqlite'
        if self.journal.is_symlink():
            raise ValueError('evidence_state_directory')
        with closing(sqlite3.connect(self.journal)) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS policy(digest TEXT PRIMARY KEY)')
            values = db.execute('SELECT digest FROM policy').fetchall()
            if values and values != [(self.plan['digest'],)]:
                raise ValueError('evidence_journal_policy')
            db.execute('INSERT OR IGNORE INTO policy VALUES(?)', (self.plan['digest'],))
            db.execute('CREATE TABLE IF NOT EXISTS entries(entry_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
            db.commit()
        os.chmod(self.journal, 0o600)

    @contextmanager
    def _lock(self):
        fd = os.open(self.root/'keeper.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _entry(self, entry):
        c = entry.get('config', {})
        if (entry.get('digest') != digest_jcs({k: v for k, v in entry.items() if k != 'digest'}) or
                self.plan['entries'].get(entry.get('entry_id')) != entry.get('digest') or
                entry.get('source_index_digest') != self.policy['worker_source_digest'] or
                c.get('evidence_quota_config') != self.policy['config_id'] or
                c.get('evidence_quota_policy_digest') != digest_jcs(self.policy) or
                c.get('deployment_epoch') != self.policy['deployment_epoch'] or
                c.get('mac_runtime_image') != self.policy['image']):
            raise ValueError('evidence_entry_binding')

    def names(self, entry):
        self._entry(entry)
        suffix = entry['digest'][7:27]
        return 'skillloop-m6-'+suffix+'-authority', 'skillloop-evidence-'+suffix

    def _save(self, entry, value):
        body = {**value, 'entry_digest': entry['digest'], 'plan_digest': self.plan['digest']}
        body['digest'] = digest_jcs(body)
        with closing(sqlite3.connect(self.journal)) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('INSERT OR REPLACE INTO entries VALUES(?,?)',
                       (entry['entry_id'], canonical_json_line(body).decode()))
            db.commit()
        return body

    def _load(self, entry):
        with closing(sqlite3.connect(self.journal)) as db:
            row = db.execute('SELECT body FROM entries WHERE entry_id=?', (entry['entry_id'],)).fetchone()
        if not row:
            return None
        b = decode_json(row[0].encode())
        if (b.get('digest') != digest_jcs({k: v for k, v in b.items() if k != 'digest'}) or
                b['entry_digest'] != entry['digest'] or b['plan_digest'] != self.plan['digest']):
            raise ValueError('evidence_journal_binding')
        return b

    @staticmethod
    def _docker(args, *, check=True):
        result = subprocess.run(['docker']+args, capture_output=True, text=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError('evidence_docker_failed')
        return result

    def _labels(self, entry):
        return {'skillloop.role': 'evidence-keeper', 'skillloop.evidence-plan': self.plan['digest'],
                'skillloop.entry': entry['digest'], 'skillloop.epoch': self.policy['deployment_epoch']}

    def _inspect_keeper(self, entry, *, live):
        volume, keeper = self.names(entry)
        data = json.loads(self._docker(['inspect', keeper]).stdout)
        if len(data) != 1:
            raise ValueError('evidence_keeper_identity')
        c = data[0]
        labels = c.get('Config', {}).get('Labels', {})
        hc = c.get('HostConfig', {})
        mount = [m for m in c.get('Mounts', []) if m['Destination'] == '/work']
        if (not re.fullmatch('[0-9a-f]{64}', c.get('Id', '')) or c.get('Image') != self.policy['image'] or
                any(labels.get(k) != v for k, v in self._labels(entry).items()) or
                hc.get('NetworkMode') != 'none' or not hc.get('ReadonlyRootfs') or
                hc.get('Memory') != 134217728 or hc.get('PidsLimit') != 16 or
                len(mount) != 1 or mount[0].get('Name') != volume or mount[0].get('RW') or
                (live and not c.get('State', {}).get('Running'))):
            raise ValueError('evidence_keeper_identity')
        state = self._load(entry)
        if state and state.get('keeper_id') and state['keeper_id'] != c['Id']:
            raise ValueError('evidence_keeper_identity')
        vol = json.loads(self._docker(['volume', 'inspect', volume]).stdout)
        if (len(vol) != 1 or vol[0].get('Options') != {'type': 'tmpfs', 'device': 'tmpfs',
                'o': f"size={self.policy['quota_bytes']},mode=0700"} or
                any(vol[0].get('Labels', {}).get(k) != v for k, v in self._labels(entry).items())):
            raise ValueError('evidence_volume_identity')
        return c

    def prepare(self, entry):
        self._entry(entry)
        with self._lock():
            state = self._load(entry)
            if state:
                if state['state'] not in {'prepared', 'creating'}:
                    raise ValueError('evidence_slot_closed')
                c = self._inspect_keeper(entry, live=True)
                if state['state'] == 'creating':
                    self._save(entry, {'state': 'prepared', 'keeper_id': c['Id'], 'volume': self.names(entry)[0]})
                return
            volume, keeper = self.names(entry)
            if self._docker(['volume', 'inspect', volume], check=False).returncode == 0:
                raise ValueError('evidence_volume_exists')
            self._save(entry, {'state': 'creating', 'volume': volume})
            labels = [a for k, v in self._labels(entry).items() for a in ('--label', k+'='+v)]
            self._docker(['volume', 'create']+labels+['--opt', 'type=tmpfs', '--opt', 'device=tmpfs',
                '--opt', f"o=size={self.policy['quota_bytes']},mode=0700", volume])
            self._docker(['run', '-d', '--name', keeper]+labels+['--network', 'none', '--read-only',
                '--memory', '128m', '--pids-limit', '16', '--cap-drop', 'ALL', '--security-opt',
                'no-new-privileges', '--mount', f'type=volume,src={volume},dst=/work,readonly',
                '--entrypoint', 'python', self.policy['image'], '-c',
                'import time; time.sleep(2147483647)'])
            c = self._inspect_keeper(entry, live=True)
            self._save(entry, {'state': 'prepared', 'keeper_id': c['Id'], 'volume': volume})

    def verify_prepared(self, entry):
        self._entry(entry)
        state = self._load(entry)
        if not state or state['state'] != 'prepared':
            raise ValueError('evidence_keeper_not_prepared')
        self._inspect_keeper(entry, live=True)

    def _stop(self, entry):
        c = self._inspect_keeper(entry, live=False)
        if c['State']['Running']:
            self._docker(['stop', '-t', '1', c['Id']])
        c = self._inspect_keeper(entry, live=False)
        if c['State']['Running']:
            raise ValueError('evidence_keeper_still_running')

    def abort_unstarted(self, entry):
        """Only the dispatcher that has not launched any worker may call this."""
        self._entry(entry)
        with self._lock():
            state = self._load(entry)
            if not state or state['state'] == 'aborted_before_worker':
                return
            if state['state'] != 'prepared':
                raise ValueError('evidence_abort_unknown')
            self._stop(entry)
            self._save(entry, {**{k: v for k, v in state.items() if k != 'digest'},
                               'state': 'aborted_before_worker'})

    def _inventory(self, target):
        target = Path(target)
        if target.is_symlink() or not target.is_dir():
            raise ValueError('evidence_export_unsafe')
        files = []
        for f in sorted(target.rglob('*')):
            if f.is_symlink() or not (f.is_file() or f.is_dir()):
                raise ValueError('evidence_export_unsafe')
            if f.is_file():
                files.append({'path': f.relative_to(target).as_posix(), 'bytes': f.stat().st_size,
                              'digest': digest_bytes(f.read_bytes())})
                if len(files) > 1024 or sum(x['bytes'] for x in files) > self.policy['quota_bytes']:
                    raise ValueError('evidence_export_size')
        return files

    @staticmethod
    def _tables(path):
        with closing(sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro&immutable=1', uri=True)) as db:
            if db.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise ValueError('evidence_backup_integrity')
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            return {t: db.execute('SELECT * FROM "'+t.replace('"', '""')+'"').fetchall() for t in tables}

    def _remote_inventory(self, entry):
        # Trusted stopped OCI controller must have written the exact keeper volume.
        volume, _ = self.names(entry)
        name = volume.removesuffix('-authority')
        values = json.loads(self._docker(['inspect', name]).stdout)
        if len(values) != 1:
            raise ValueError('evidence_controller_identity')
        c = values[0]
        mounts = [x for x in c.get('Mounts', []) if x['Destination'] == '/work']
        if (c.get('Image') != self.policy['image'] or c.get('State', {}).get('Running') or
                c.get('State', {}).get('ExitCode') != 0 or len(mounts) != 1 or
                mounts[0].get('Name') != volume or not mounts[0].get('RW')):
            raise ValueError('evidence_controller_identity')
        component = entry['case_id']+'.'+entry['role']+'.'+str(entry['repetition'])
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', component) or component in {'.', '..'}:
            raise ValueError('evidence_export_path')
        keeper = self._inspect_keeper(entry, live=True)
        program = """import hashlib,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);limit=int(sys.argv[2]);files=[];total=0
assert root.is_dir() and not root.is_symlink()
for f in sorted(root.rglob('*')):
 assert not f.is_symlink() and (f.is_file() or f.is_dir())
 if not f.is_file():continue
 size=f.stat().st_size;total+=size;assert total<=limit and len(files)<1024
 h=hashlib.sha256()
 with f.open('rb') as stream:
  while True:
   block=stream.read(1048576)
   if not block:break
   h.update(block)
 files.append({'path':f.relative_to(root).as_posix(),'bytes':size,'digest':'sha256:'+h.hexdigest()})
print(json.dumps(files))
"""
        result = self._docker(['exec', keeper['Id'], 'python', '-c', program,
                               '/work/'+component, str(self.policy['quota_bytes'])])
        return decode_json(result.stdout.encode())

    def verify_and_close(self, entry, target):
        self._entry(entry)
        with self._lock():
            state = self._load(entry)
            if not state or state['state'] not in {'prepared', 'export_verified', 'closed'}:
                raise ValueError('evidence_keeper_not_prepared')
            files = self._inventory(target)
            if state['state'] in {'export_verified', 'closed'}:
                if state['receipt']['files'] != files or state['receipt']['export_root'] != str(Path(target).absolute()):
                    raise ValueError('evidence_export_changed')
            else:
                self.verify_prepared(entry)
                if self._remote_inventory(entry) != files:
                    raise ValueError('evidence_oci_export_mismatch')
                required = {'result.json', 'authority.db', 'authority.backup.db'}
                if not required <= {x['path'] for x in files}:
                    raise ValueError('evidence_export_incomplete')
                for name in ('authority.db-wal', 'authority.backup.db-wal'):
                    if (Path(target)/name).exists() and (Path(target)/name).stat().st_size:
                        raise ValueError('evidence_export_uncheckpointed')
                if self._tables(Path(target)/'authority.db') != self._tables(Path(target)/'authority.backup.db'):
                    raise ValueError('evidence_backup_mismatch')
                receipt = {'kind': 'VerifiedQuotaExport', 'entry_digest': entry['digest'],
                           'plan_digest': self.plan['digest'], 'export_root': str(Path(target).absolute()),
                           'files': files, 'consistent_backup': True}
                receipt['digest'] = digest_jcs(receipt)
                state = self._save(entry, {**{k: v for k, v in state.items() if k != 'digest'},
                    'state': 'export_verified', 'receipt': receipt})
            if state['state'] != 'closed':
                self._stop(entry)
                state = self._save(entry, {**{k: v for k, v in state.items() if k != 'digest'}, 'state': 'closed'})
            return state['receipt']
