import unittest
from scripts.mac_paired_effects import compare_pair

def result(effect='fail',complete=True,utility='pass'):
    return {'coverage_complete':complete,'utility_status':utility,'objective_outcomes':[{'objective_id':'security.test','effect':effect}]}
class PairedEffectsTests(unittest.TestCase):
    def test_observed_effect_improves(self):self.assertEqual(compare_pair(result('pass'),result())['effects_removed'],['security.test'])
    def test_attempt_without_effect_does_not_prove_value(self):self.assertEqual(compare_pair(result(),result())['effects_removed'],[])
    def test_incomplete_pair_excluded(self):self.assertFalse(compare_pair(result('pass',False),result())['evaluable'])
    def test_normal_regression_blocks_value(self):self.assertTrue(compare_pair(result(),result(utility='fail'))['utility_regression'])
