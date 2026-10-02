"""Physical Linux reservation and real SQLite admission behavior."""
import importlib.util
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from skillloop.families.task_world import fixture, stamp
from skillloop.protocol import digest_jcs
from skillloop.proxy.store import ProxyError


@unittest.skipUnless(hasattr(os, 'posix_fallocate'), 'Linux physical allocation required')
class ReservedQueueTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('skillloop.runtime.reserved_queue'),
                             'physical queue admission adapter is missing')
        from skillloop.runtime.reserved_queue import ReservedProxyStore
        self.Store = ReservedProxyStore
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = dict(deployment_epoch='queue-test-1', queue_capacity=2,
                         reservation_bytes=4096, free_floor_bytes=4096)
        self.store = self.Store(self.root/'authority.db', **self.args)
        self.requests = {}
        for n in range(6):
            domain, policy, binding, request, approval, raw = fixture(
                run_id=f'run-{n}', task_instance_id=f'task-{n}')
            if n == 0:
                approval_ref = approval['digest']
                self.store.stage_approval(domain, approval)
                self.store.activate_approval(approval['digest'], 0, operation_id='activate',
                                            request_digest=digest_jcs('activate'))
            self.store.stage_task(domain=domain, policy=policy, binding=binding,
                                 run_request=request, profile_id='orders_total', resources=raw,
                                 approval_digest=approval_ref, run_deadline=stamp(240),
                                 campaign_id='queue-test-campaign')
            self.requests[n] = (request['digest'], binding['digest'])

    def start(self, n):
        return self.store.start_run(*self.requests[n], operation_id=f'start-{n}',
                                    request_digest=digest_jcs(f'start-{n}'))

    def held(self):
        with sqlite3.connect(self.root/'authority.db') as db:
            return db.execute("SELECT run_id,filename FROM storage_reservations WHERE state='held'").fetchall()

    def test_start_has_physical_reservation_before_run_commit(self):
        self.start(0)
        rows = self.held()
        self.assertEqual([x[0] for x in rows], ['run-0'])
        st = (self.store.reservation_directory/rows[0][1]).stat()
        self.assertEqual(st.st_size, 4096)
        self.assertGreaterEqual(st.st_blocks*512, 4096)
        self.assertEqual(self.start(0)['body']['fencing_token'], 1)
        self.assertEqual(len(self.held()), 1)

    def test_full_queue_rolls_back_run_and_operation(self):
        self.start(0); self.start(1)
        with self.assertRaisesRegex(ProxyError, 'queue_full'):
            self.start(2)
        with sqlite3.connect(self.root/'authority.db') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM operations WHERE operation_id='start-2'").fetchone()[0], 0)
        self.assertEqual(len(list(self.store.reservation_directory.glob('*.reserve'))), 2)

    def test_concurrent_start_cannot_overbook(self):
        def attempt(n):
            try: self.start(n); return 'accepted'
            except ProxyError as e: return e.code
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(attempt, range(6)))
        self.assertEqual(results.count('accepted'), 2)
        self.assertEqual(results.count('queue_full'), 4)
        self.assertEqual(len(self.held()), 2)

    def test_cancel_replay_releases_once_and_allows_next_start(self):
        self.start(0); self.start(1)
        args = dict(operation_id='cancel-0', request_digest=digest_jcs('cancel-0'))
        first = self.store.cancel_run('run-0', 1, **args)
        self.assertEqual(self.store.cancel_run('run-0', 1, **args), first)
        self.assertEqual(first['fence'], 2)
        self.start(2)
        self.assertEqual({x[0] for x in self.held()}, {'run-1', 'run-2'})

    def test_restart_keeps_capacity_and_refuses_policy_change(self):
        self.start(0); self.start(1)
        self.store = self.Store(self.root/'authority.db', **self.args)
        with self.assertRaisesRegex(ProxyError, 'queue_full'): self.start(2)
        with self.assertRaisesRegex(ProxyError, 'reservation_policy_mismatch'):
            self.Store(self.root/'authority.db', **{**self.args, 'queue_capacity': 3})
        with self.assertRaisesRegex(ProxyError, 'deployment_epoch_mismatch'):
            self.Store(self.root/'authority.db', **{**self.args, 'deployment_epoch': 'old-epoch'})

    def test_missing_reserved_file_fails_closed(self):
        self.start(0)
        (self.store.reservation_directory/self.held()[0][1]).unlink()
        with self.assertRaisesRegex(ProxyError, 'reservation_evidence_missing'):
            self.start(1)
        with sqlite3.connect(self.root/'authority.db') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0], 1)

    def test_free_floor_refuses_before_start(self):
        other = self.root/'floor.db'
        huge = self.Store(other, **{**self.args, 'free_floor_bytes': 1 << 40})
        d,p,b,r,a,raw = fixture()
        huge.stage_approval(d,a); huge.activate_approval(a['digest'],0,operation_id='activate',request_digest=digest_jcs('activate'))
        huge.stage_task(domain=d,policy=p,binding=b,run_request=r,profile_id='orders_total',resources=raw,approval_digest=a['digest'],run_deadline=stamp(240),campaign_id='floor')
        with self.assertRaisesRegex(ProxyError, 'storage_floor'):
            huge.start_run(r['digest'],b['digest'],operation_id='start',request_digest=digest_jcs('start'))
        with sqlite3.connect(other) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0], 0)

    def test_before_commit_failure_cleans_uncommitted_file(self):
        def fail(point):
            if point == 'before_commit': raise RuntimeError('crash-before-commit')
        self.store.fault_hook = fail
        with self.assertRaisesRegex(RuntimeError, 'crash-before-commit'): self.start(0)
        self.store.fault_hook = None
        self.assertEqual(self.held(), [])
        self.assertEqual(list(self.store.reservation_directory.glob('*.reserve')), [])
        self.start(0)

    def test_policy_rejects_unsafe_integer_before_initializing(self):
        with self.assertRaisesRegex(ValueError, 'reservation_policy_invalid'):
            self.Store(self.root/'unsafe.db', **{**self.args, 'free_floor_bytes': 1 << 60})
        self.assertFalse((self.root/'unsafe.db').exists())

    def test_truncated_reservation_cannot_admit_new_run(self):
        self.start(0)
        path = self.store.reservation_directory/self.held()[0][1]
        with path.open('r+b') as f: f.truncate(1)
        with self.assertRaisesRegex(ProxyError, 'reservation_evidence_missing'):
            self.start(1)

    def test_existing_unreserved_run_is_not_silently_adopted(self):
        from skillloop.proxy.store import ProxyStore
        base = ProxyStore(self.root/'authority.db', deployment_epoch='queue-test-1')
        base.start_run(*self.requests[0], operation_id='unreserved-start',
                       request_digest=digest_jcs('unreserved-start'))
        with self.assertRaisesRegex(ProxyError, 'unreserved_existing_run'):
            self.Store(self.root/'authority.db', **self.args)

    def test_live_store_refuses_run_inserted_outside_admission(self):
        from skillloop.proxy.store import ProxyStore
        base = ProxyStore(self.root/'authority.db', deployment_epoch='queue-test-1')
        base.start_run(*self.requests[0], operation_id='unreserved-start',
                       request_digest=digest_jcs('unreserved-start'))
        with self.assertRaisesRegex(ProxyError, 'unreserved_existing_run'):
            self.start(1)
        self.assertEqual(self.held(), [])

    def test_controller_can_cancel_run_after_reservation_loss(self):
        self.start(0)
        (self.store.reservation_directory/self.held()[0][1]).unlink()
        result = self.store.cancel_run('run-0',1,operation_id='withdraw-lost-space',
                                      request_digest=digest_jcs('withdraw-lost-space'))
        self.assertEqual(result['fence'], 2)
        self.assertEqual(self.held(), [])
        self.start(1)

    def test_active_run_with_released_reservation_fails_closed(self):
        self.start(0)
        with sqlite3.connect(self.root/'authority.db') as db:
            db.execute("UPDATE storage_reservations SET state='released' WHERE run_id='run-0'")
        with self.assertRaisesRegex(ProxyError, 'unreserved_existing_run'):
            self.start(1)

    def test_after_commit_error_preserves_committed_reservation(self):
        def fail(point):
            if point == 'after_commit': raise RuntimeError('lost-ack')
        self.store.fault_hook = fail
        with self.assertRaisesRegex(RuntimeError, 'lost-ack'): self.start(0)
        self.store.fault_hook = None
        self.store = self.Store(self.root/'authority.db', **self.args)
        self.assertEqual(len(self.held()), 1)
        self.assertEqual(self.start(0)['body']['fencing_token'], 1)

    def test_restart_cleans_cancelled_file_after_lost_ack(self):
        self.start(0)
        def fail(point):
            if point == 'after_commit': raise RuntimeError('lost-ack')
        self.store.fault_hook = fail
        with self.assertRaisesRegex(RuntimeError, 'lost-ack'):
            self.store.cancel_run('run-0',1,operation_id='cancel',request_digest=digest_jcs('cancel'))
        self.store = self.Store(self.root/'authority.db', **self.args)
        self.assertEqual(self.held(), [])
        self.assertEqual(list(self.store.reservation_directory.glob('*.reserve')), [])


if __name__ == '__main__': unittest.main()
