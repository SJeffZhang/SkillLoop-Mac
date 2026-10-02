import unittest
from skillloop.ci.qualification import qualification_outcome
class QualificationTests(unittest.TestCase):
    def test_pass(self):self.assertEqual(qualification_outcome('pass'),{'exit_code':0,'conclusion':'success'})
    def test_fail(self):self.assertEqual(qualification_outcome('fail'),{'exit_code':1,'conclusion':'failure'})
    def test_inconclusive_blocks(self):self.assertEqual(qualification_outcome('inconclusive'),{'exit_code':3,'conclusion':'failure'})
    def test_contract_blocks(self):self.assertEqual(qualification_outcome('needs_contract'),{'exit_code':4,'conclusion':'action_required'})
    def test_unknown_rejected(self):
        for v in ['neutral','skipped','unknown',None,True]:
            with self.assertRaises(ValueError):qualification_outcome(v)
