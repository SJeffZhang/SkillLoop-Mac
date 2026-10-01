import copy
import unittest
from skillloop.protocol import digest_jcs
from skillloop.protection.mac_admission import admit_profile


def seal(body):
    return {**body, 'digest': digest_jcs(body)}

class MacM7AdmissionTests(unittest.TestCase):
    def fixtures(self):
        manifest=seal({'config':{'worker_deadline_seconds':265},'profiles':{'orders':{'required_runs':2,'inheritance':{'candidate_subject_digest':'candidate'}}}})
        freeze=seal({'subject':'candidate','status':'frozen','reasons':[]})
        gate=seal({'campaign_digest':manifest['digest'],'config_digest':digest_jcs(manifest['config']),'profiles':{'orders':{'verdict':'pass','errors':[],'missing':[],'actual_attempts':2,'freeze':freeze}}})
        clock=seal({'manifest_digest':manifest['digest'],'started_at':1000})
        executions=[{'item_key':k,'attempt':0} for k in ['capacity.1','capacity.2','formal.1','formal.2']]
        ledger={'executions':executions,'victim_attempts':4,'retries':0,'charged_wall_seconds':1060,'elapsed_seconds':100,'campaign_started_at':1000}
        return gate,manifest,clock,ledger,executions
    def test_ready_keeps_spending_prefix(self):
        g,m,c,l,e=self.fixtures();r=admit_profile(g,m,c,l,profile='orders',expected_executions=e,at_unix_ms=1100000)
        self.assertEqual(r['admission'],'ready');self.assertEqual(r['protected_required_runs'],24);self.assertEqual(r['prior_spending_digest'],digest_jcs(l))
    def test_inconclusive_cannot_enter(self):
        g,m,c,l,e=self.fixtures();g['profiles']['orders']['verdict']='inconclusive';g=seal({k:v for k,v in g.items() if k!='digest'})
        with self.assertRaisesRegex(ValueError,'m6_not_qualified'):admit_profile(g,m,c,l,profile='orders',expected_executions=e,at_unix_ms=1100000)
    def test_clock_cannot_restart(self):
        g,m,c,l,e=self.fixtures();l['campaign_started_at']=1100
        with self.assertRaisesRegex(ValueError,'spending'):admit_profile(g,m,c,l,profile='orders',expected_executions=e,at_unix_ms=1100000)
    def test_no_extra_or_duplicate_slots(self):
        g,m,c,l,e=self.fixtures();l=copy.deepcopy(l);l['executions'].append(l['executions'][0])
        with self.assertRaisesRegex(ValueError,'spending'):admit_profile(g,m,c,l,profile='orders',expected_executions=e,at_unix_ms=1100000)
    def test_full_protection_must_fit_original_clock(self):
        g,m,c,l,e=self.fixtures();r=admit_profile(g,m,c,l,profile='orders',expected_executions=e,at_unix_ms=28000000)
        self.assertEqual(r['admission'],'rejected')
