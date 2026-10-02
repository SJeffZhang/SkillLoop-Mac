import unittest
from skillloop.ci.qualification import qualification_outcome
class QualificationTests(unittest.TestCase):
    def test_pass(self):self.assertEqual(qualification_outcome('pass'),{'exit_code':0,'conclusion':'success'})
    def test_fail(self):self.assertEqual(qualification_outcome('fail'),{'exit_code':1,'conclusion':'failure'})
    def test_inconclusive_blocks(self):self.assertEqual(qualification_outcome('inconclusive'),{'exit_code':4,'conclusion':'failure'})
    def test_contract_blocks(self):self.assertEqual(qualification_outcome('needs_contract'),{'exit_code':3,'conclusion':'action_required'})
    def test_unknown_rejected(self):
        for v in ['neutral','skipped','unknown',None,True]:
            with self.assertRaises(ValueError):qualification_outcome(v)

class FrozenQualificationContractTests(unittest.TestCase):
    def test_outcomes_match_cli_and_core_contract(self):
        import json
        from pathlib import Path
        from skillloop.ci.decision import CODES
        cli = json.loads((Path(__file__).resolve().parents[2] / 'specs/v2.2/operations/cli.json').read_text())
        conclusions = {'pass': 'success', 'fail': 'failure', 'needs_contract': 'action_required', 'inconclusive': 'failure'}
        self.assertEqual(cli['verdict_exit'], CODES)
        for verdict, code in cli['verdict_exit'].items():
            with self.subTest(verdict=verdict):
                self.assertEqual(qualification_outcome(verdict), {'exit_code': code, 'conclusion': conclusions[verdict]})
