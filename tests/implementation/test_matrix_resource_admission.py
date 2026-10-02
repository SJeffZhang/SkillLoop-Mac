import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import mac_m6_matrix as matrix
from skillloop.protocol import digest_jcs
from skillloop.repair.budget import SpendingLedger


class MatrixResourceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = {'kind': 'formal', 'profile': 'orders_total', 'entry_id': 'new-0',
                      'case_id': 'case', 'role': 'submitted', 'repetition': 0,
                      'config': {'worker_deadline_seconds': 265, 'model_service_port': 1,
                                 'mac_runtime_image': 'image'}}
        self.entry['digest'] = digest_jcs(self.entry)
        self.path = self.root/'entry.json'
        matrix.save(self.path, self.entry)
        self.ledger = SpendingLedger(self.root/'spending.json', victim_seconds=265)
        self.admission = Mock()

    def execute(self):
        return matrix.execute(self.root, self.root, self.entry, self.ledger,
                              entry_path=self.path, resource_admission=self.admission)

    def test_reservation_precedes_durable_spending(self):
        events = []
        self.admission.reserve.side_effect = lambda entry: events.append(('reserve', self.ledger.read()['victim_attempts']))
        real_consume = self.ledger.consume
        def consume(*args):
            events.append(('consume', 0))
            return real_consume(*args)
        self.ledger.consume = consume
        with patch.object(matrix, 'model_identity'), patch.object(matrix.subprocess, 'run', return_value=Mock(returncode=1)):
            self.assertEqual(self.execute(), 'controller_failed')
        self.assertEqual(events, [('reserve', 0), ('consume', 0)])
        self.assertEqual(self.ledger.read()['victim_attempts'], 1)
        # A failed controller alone does not prove all detached workers stopped.
        self.admission.release.assert_not_called()

    def test_full_queue_never_consumes_or_launches_worker(self):
        self.admission.reserve.side_effect = ValueError('queue_full')
        with patch.object(matrix, 'model_identity'), patch.object(matrix.subprocess, 'run') as worker:
            with self.assertRaisesRegex(ValueError, 'queue_full'):
                self.execute()
            worker.assert_not_called()
        self.assertEqual(self.ledger.read()['victim_attempts'], 0)
        self.admission.release.assert_not_called()

    def test_budget_failure_releases_reservation(self):
        self.ledger.consume = Mock(side_effect=ValueError('execution_budget_exhausted'))
        with patch.object(matrix, 'model_identity'), patch.object(matrix.subprocess, 'run') as worker:
            with self.assertRaisesRegex(ValueError, 'execution_budget_exhausted'):
                self.execute()
            worker.assert_not_called()
        self.admission.release.assert_called_once_with(self.entry)

    def test_unknown_container_launch_retains_spent_and_reservation(self):
        with patch.object(matrix, 'model_identity'), patch.object(matrix.subprocess, 'run', side_effect=OSError('transport lost')):
            with self.assertRaises(OSError):
                self.execute()
        self.assertEqual(self.ledger.read()['victim_attempts'], 1)
        self.admission.release.assert_not_called()

    def test_existing_spent_slot_is_never_readmitted(self):
        self.ledger.consume(self.entry['entry_id'], 0)
        with patch.object(matrix.subprocess, 'run', return_value=Mock(returncode=1)):
            self.assertEqual(self.execute(), 'consumed_without_container')
        self.admission.reserve.assert_not_called()

    def test_invalid_entry_never_reserves(self):
        self.path.unlink()
        with self.assertRaisesRegex(ValueError, 'entry_bind_source_not_file'):
            self.execute()
        self.admission.reserve.assert_not_called()
        self.assertEqual(self.ledger.read()['victim_attempts'], 0)

    def test_unverified_export_keeps_reservation(self):
        with patch.object(matrix, 'model_identity'), patch.object(matrix.subprocess, 'run', return_value=Mock(returncode=0)):
            self.assertEqual(self.execute(), 'export_failed')
        self.admission.release.assert_not_called()
        self.assertEqual(self.ledger.read()['victim_attempts'], 1)

    def test_cli_legacy_requires_no_resource_adapter(self):
        args = SimpleNamespace(resource_admission_plan=None, resource_admission_state=None,
                               resource_admission_socket=None)
        self.assertIsNone(matrix.resource_admission_from_args(args, {}))

    def test_cli_partial_configuration_is_rejected(self):
        args = SimpleNamespace(resource_admission_plan=self.path, resource_admission_state=None,
                               resource_admission_socket=None)
        with self.assertRaisesRegex(ValueError, 'resource_admission_arguments'):
            matrix.resource_admission_from_args(args, {})

    def test_cli_wrong_manifest_is_rejected_before_adapter(self):
        plan = {'config_id': 'new', 'manifest_digest': digest_jcs('other')}
        plan['digest'] = digest_jcs(plan)
        matrix.save(self.path, plan)
        args = SimpleNamespace(resource_admission_plan=self.path, resource_admission_state=self.root/'state',
                               resource_admission_socket=self.root/'sockets')
        with self.assertRaisesRegex(ValueError, 'resource_admission_manifest'):
            matrix.resource_admission_from_args(args, {'digest': digest_jcs('manifest'),
                'config': {'resource_admission_config': 'new'}})

    def test_completed_export_resumes_pending_release_without_spending(self):
        target = matrix.result_path(self.root, self.entry)
        target.parent.mkdir(parents=True)
        target.write_text('{}')
        self.ledger.consume(self.entry['entry_id'], 0)
        before = self.ledger.read()
        with patch.object(matrix.subprocess, 'run') as worker:
            self.assertEqual(self.execute(), 'retained_completed')
            worker.assert_not_called()
        self.admission.release.assert_called_once_with(self.entry)
        self.admission.reserve.assert_not_called()
        self.assertEqual(self.ledger.read(), before)


if __name__ == '__main__':
    unittest.main()
