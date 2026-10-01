import os,unittest
from scripts.spec_v22_families import generate_private_suite,validate_private_suite
from skillloop.discovery.suite import compile_dev_suite
from skillloop.protection.suite import compile_private
from scripts.mac_m7_gate import rebuild_private_bundle,paired_verdict
from tests.implementation.test_mac_m7_entries import Count

class PrivateGateTests(unittest.TestCase):
    def test_factory_reconstruction_matches_raw_inputs_and_payloads(self):
        b=generate_private_suite('orders_total',os.urandom(32));c=compile_private(b,Count(),compile_dev_suite('orders_total'))
        rebuilt=rebuild_private_bundle(c,b['inputs'],b['epoch_id']);self.assertEqual(validate_private_suite(rebuilt),validate_private_suite(b));self.assertEqual(compile_private(rebuilt,Count(),compile_dev_suite('orders_total')),c)
    def test_missing_submitted_is_inconclusive_even_with_safe_finalist(self):
        self.assertEqual(paired_verdict(False,[],['missing']), 'inconclusive')
    def test_confirmed_finalist_failure_is_sticky(self):
        self.assertEqual(paired_verdict(True,[],['missing']), 'fail')
    def test_complete_verified_pair_passes(self):self.assertEqual(paired_verdict(False,[],[]),'pass')

class AttestationTests(unittest.TestCase):
    def test_chain_refuses_empty_execution_index(self):
        from scripts.mac_m7_gate import api4_chain
        with self.assertRaisesRegex(ValueError,'attestation_requires_execution_records'):
            api4_chain({}, {}, [], {}, {}, {})

class PairedApi4Tests(unittest.TestCase):
    def test_failed_baseline_does_not_disqualify_passing_finalist(self):
        from scripts.mac_m7_gate import api4_pair_verdict
        self.assertEqual(api4_pair_verdict({'submitted':'fail','finalist':'pass'}),'pass')
    def test_incomplete_baseline_blocks_qualification(self):
        from scripts.mac_m7_gate import api4_pair_verdict
        self.assertEqual(api4_pair_verdict({'submitted':'inconclusive','finalist':'pass'}),'inconclusive')
