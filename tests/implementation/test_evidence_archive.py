import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from skillloop.ci.registry import LocalRegistry
from skillloop.protocol import digest_bytes, digest_jcs


class ClosedArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capsule = self.root / 'inactive-evidence'
        self.capsule.mkdir(mode=0o700)
        (self.capsule / 'raw.json').write_bytes(b'{"raw":true}\n')
        self.inventory = {'raw.json': {'digest': digest_bytes(b'{"raw":true}\n'), 'bytes': 13}}
        self.registry = LocalRegistry(self.root / 'registry.sqlite')
        self.trigger = self.registry.trigger('project', 'a' * 40, 'config')
        self.decision = {'verdict': 'pass', 'scope': 'local_authority_exact_pr_experiment', 'production_ready': False}
        receipt = self.registry.complete('project', 'a' * 40, 'config', **self.trigger_args(), decision=self.decision)
        self.binding = {'project': 'project', 'head': 'a' * 40, 'config': 'config', **self.trigger_args(), 'receipt_digest': receipt}

    def trigger_args(self):
        return {k: self.trigger[k] for k in ('generation', 'campaign')}

    def service(self, **kwargs):
        from skillloop.ci.evidence_archive import ClosedExperimentArchive
        return ClosedExperimentArchive(self.root, self.inventory, self.binding, config='archive-v1', **kwargs)

    def state(self):
        with sqlite3.connect(self.registry.path) as db:
            return json.loads(db.execute('SELECT body FROM evidence_archives').fetchone()[0])

    def test_withdraw_export_retire_and_restart(self):
        service = self.service()
        withdrawal = service.withdraw()
        self.assertEqual(withdrawal['generation'], 2)
        self.assertEqual(self.service().withdraw(), withdrawal)
        with self.assertRaisesRegex(ValueError, 'stale_generation'):
            self.registry.complete('project', 'a' * 40, 'config', **self.trigger_args(), decision=self.decision)
        exported = service.export()
        self.assertTrue(self.capsule.exists())
        self.assertEqual(exported['state'], 'export_verified')
        retired = self.service().retire()
        self.assertFalse(self.capsule.exists())
        self.assertEqual(retired['state'], 'retired')
        self.assertEqual(self.service().retire(), retired)
        with sqlite3.connect(self.registry.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM receipts').fetchone()[0], 1)

    def test_no_export_or_retirement_without_withdrawal(self):
        for method in ('export', 'retire'):
            with self.assertRaisesRegex(ValueError, 'withdrawal_required'):
                getattr(self.service(), method)()
        self.assertTrue(self.capsule.exists())

    def test_wrong_receipt_does_not_withdraw(self):
        self.binding['receipt_digest'] = digest_jcs('wrong')
        with self.assertRaisesRegex(ValueError, 'receipt_binding'):
            self.service().withdraw()
        with sqlite3.connect(self.registry.path) as db:
            self.assertEqual(db.execute('SELECT generation FROM projects').fetchone()[0], 1)

    def test_tampered_source_does_not_withdraw(self):
        (self.capsule / 'raw.json').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'inventory_mismatch'):
            self.service().withdraw()

    def test_tampered_archive_keeps_source_and_withdrawal(self):
        service = self.service()
        service.withdraw()
        service.export()
        (self.root / 'evidence.tar').write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'archive_digest'):
            service.retire()
        self.assertTrue(self.capsule.exists())
        self.assertEqual(self.state()['state'], 'export_verified')

    def test_source_changed_after_export_keeps_source(self):
        service = self.service()
        service.withdraw()
        service.export()
        (self.capsule / 'raw.json').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'inventory_mismatch'):
            service.retire()
        self.assertTrue(self.capsule.exists())

    def test_symlink_is_rejected(self):
        (self.capsule / 'raw.json').unlink()
        (self.capsule / 'raw.json').symlink_to(self.root / 'registry.sqlite')
        with self.assertRaisesRegex(ValueError, 'unsafe_evidence'):
            self.service().withdraw()

    def test_traversal_inventory_is_rejected(self):
        self.inventory['../registry.sqlite'] = self.inventory.pop('raw.json')
        with self.assertRaisesRegex(ValueError, 'unsafe_inventory'):
            self.service()

    def test_export_before_delete_crash_is_resumable(self):
        service = self.service()
        service.withdraw()
        service.export()
        def crash(phase):
            if phase == 'before_remove':
                raise RuntimeError('injected_crash')
        with self.assertRaisesRegex(RuntimeError, 'injected_crash'):
            self.service(fault_hook=crash).retire()
        self.assertTrue((self.root / 'retiring-evidence').exists())
        self.assertEqual(self.service().retire()['state'], 'retired')

    def test_changed_generation_prevents_retirement(self):
        service = self.service()
        service.withdraw()
        service.export()
        self.registry.trigger('project', 'b' * 40, 'config')
        with self.assertRaisesRegex(ValueError, 'archive_generation'):
            service.retire()
        self.assertTrue(self.capsule.exists())

    def test_partial_removal_crash_is_resumable(self):
        (self.capsule / 'more.json').write_bytes(b'{}')
        self.inventory['more.json'] = {'digest': digest_bytes(b'{}'), 'bytes': 2}
        service = self.service()
        service.withdraw()
        service.export()
        def crash(phase):
            if phase == 'file_removed':
                raise RuntimeError('partial_crash')
        with self.assertRaisesRegex(RuntimeError, 'partial_crash'):
            self.service(fault_hook=crash).retire()
        self.assertEqual(self.state()['state'], 'retiring')
        self.assertEqual(self.service().retire()['state'], 'retired')

    def test_new_capsule_during_retirement_is_rejected(self):
        service = self.service()
        service.withdraw()
        service.export()
        def crash(phase):
            raise RuntimeError('crash')
        with self.assertRaises(RuntimeError):
            self.service(fault_hook=crash).retire()
        self.capsule.mkdir()
        with self.assertRaisesRegex(ValueError, 'ambiguous_evidence_directory'):
            self.service().retire()

    def test_incomplete_preexisting_export_is_not_overwritten(self):
        service = self.service()
        service.withdraw()
        bad = self.root / 'evidence.tar'
        bad.write_bytes(b'partial')
        with self.assertRaises(Exception):
            service.export()
        self.assertEqual(bad.read_bytes(), b'partial')
        self.assertTrue(self.capsule.exists())
        self.assertEqual(self.state()['state'], 'withdrawn')

    def test_production_receipt_is_rejected(self):
        body = {'verdict': 'pass', 'scope': 'production', 'production_ready': True}
        with sqlite3.connect(self.registry.path) as db:
            db.execute('UPDATE receipts SET digest=?,body=?', (digest_jcs(body), json.dumps(body)))
        self.binding['receipt_digest'] = digest_jcs(body)
        with self.assertRaisesRegex(ValueError, 'closed_experiment_scope_required'):
            self.service().withdraw()


if __name__ == '__main__':
    unittest.main()
