import json
import tempfile
import unittest
from pathlib import Path

from skillloop.protocol import digest_jcs
from skillloop.proxy.wire import make_control
from skillloop.families.task_world import stamp
from scripts.spec_v22_core import envelope


class ControllerReservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = {'entry_id': 'entry', 'source_index_digest': digest_jcs('source'),
                      'config': {'resource_admission_config': 'admission-v1'}}
        self.entry['digest'] = digest_jcs(self.entry)
        self.plan = {'config_id': 'admission-v1', 'manifest_digest': digest_jcs('manifest'),
                     'source_digest': self.entry['source_index_digest'],
                     'entries': {self.entry['digest']: {'entry_id': 'entry', 'run_id': 'run',
                         'campaign_id': 'campaign', 'run_request_digest': digest_jcs('request'),
                         'task_binding_digest': digest_jcs('binding')}}}
        self.plan['digest'] = digest_jcs(self.plan)
        self.calls = []

    def rpc(self, request):
        self.calls.append(request)
        if request['body']['method'] == 'start_run':
            return envelope('Lease', {'campaign_id': 'campaign', 'run_id': 'run', 'worker_id': 'trusted-runtime',
                'fencing_token': 1, 'expires_at': stamp(240), 'state': 'active'})
        return make_control('CancellationResult', {'campaign_public_ref': 'campaign', 'run_id': 'run',
            'effective_fence': 2, 'committed_at': stamp(0)})

    def service(self, rpc=None):
        from skillloop.runtime.controller_reservation import ControllerResourceAdmission
        value = ControllerResourceAdmission(self.plan, self.root/'admission.sqlite', self.root/'sockets')
        value._rpc = rpc or self.rpc
        return value

    def test_reserve_restart_cancel_is_idempotent(self):
        lease = self.service().reserve(self.entry)
        self.assertEqual(self.service().reserve(self.entry), lease)
        self.assertEqual(len(self.calls), 1)
        result = self.service().release(self.entry)
        self.assertEqual(self.service().release(self.entry), result)
        self.assertEqual(len(self.calls), 2)
        with self.assertRaisesRegex(ValueError, 'reservation_released'):
            self.service().reserve(self.entry)

    def test_entry_binding_refuses_before_rpc(self):
        changed = dict(self.entry, entry_id='different')
        with self.assertRaisesRegex(ValueError, 'reservation_entry_binding'):
            self.service().reserve(changed)
        self.assertEqual(self.calls, [])

    def test_wrong_lease_run_is_rejected(self):
        def wrong(request):
            result = self.rpc(request)
            result['body']['run_id'] = 'other'
            result['digest'] = digest_jcs({k: v for k, v in result.items() if k != 'digest'})
            return result
        with self.assertRaisesRegex(ValueError, 'reservation_lease_binding'):
            self.service(wrong).reserve(self.entry)

    def test_transport_unknown_is_preserved(self):
        def lost(request):
            raise OSError('lost ACK')
        with self.assertRaises(OSError):
            self.service(lost).reserve(self.entry)
        lease = self.service().reserve(self.entry)
        self.assertEqual(lease['body']['run_id'], 'run')
        self.assertEqual(len(self.calls), 1)

    def test_state_config_change_is_rejected(self):
        self.service().reserve(self.entry)
        self.plan['config_id'] = 'changed'
        self.plan['digest'] = digest_jcs({k: v for k, v in self.plan.items() if k != 'digest'})
        with self.assertRaisesRegex(ValueError, 'reservation_plan_changed'):
            self.service()

    def test_wrong_cancel_fence_is_rejected(self):
        self.service().reserve(self.entry)
        def wrong(request):
            value = self.rpc(request)
            return make_control('CancellationResult', {**value['body'], 'effective_fence': 3})
        with self.assertRaisesRegex(ValueError, 'reservation_cancel_binding'):
            self.service(wrong).release(self.entry)


if __name__ == '__main__':
    unittest.main()
