import unittest
from datetime import datetime,timezone,timedelta
from skillloop.protocol import make_envelope
from skillloop.ci.attestation_consumption import validate_consumption

class ConsumptionTests(unittest.TestCase):
    def setUp(self):
        import json
        from pathlib import Path
        self.a=json.loads(Path('specs/v2.2/core/required-run-chain.json').read_text())['attestation']
        self.b=self.a['body'];self.issued=datetime.fromisoformat(self.b['issued_at'].replace('Z','+00:00'));self.expiry=datetime.fromisoformat(self.b['expires_at'].replace('Z','+00:00'))
        self.kw={'verified_attestation_digest':self.a['digest'],'expected_bindings':{k:self.b[k] for k in ('subject_digest','plan_digest','suite_digest','config_digest','issuer','trust_revision')}}
    def check(self,now,**changes):return validate_consumption(self.a,now=now,**{**self.kw,**changes})
    def test_before_expiry(self):self.assertEqual(self.check(self.expiry-timedelta(seconds=1)),self.a)
    def test_at_and_after_expiry(self):
        for n in (self.expiry,self.expiry+timedelta(seconds=1)):
            with self.assertRaisesRegex(ValueError,'expired'):self.check(n)
    def test_before_issue(self):
        with self.assertRaisesRegex(ValueError,'not_yet_valid'):self.check(self.issued-timedelta(seconds=1))
    def test_naive_clock(self):
        with self.assertRaisesRegex(ValueError,'trusted_clock'):self.check(self.issued.replace(tzinfo=None))
    def test_unverified_digest(self):
        with self.assertRaisesRegex(ValueError,'unverified'):self.check(self.issued,verified_attestation_digest='sha256:'+'0'*64)
    def test_each_frozen_binding(self):
        for k in self.kw['expected_bindings']:
            with self.assertRaisesRegex(ValueError,'binding'):self.check(self.issued,expected_bindings={**self.kw['expected_bindings'],k:'wrong'})
    def test_missing_binding(self):
        with self.assertRaisesRegex(ValueError,'bindings'):self.check(self.issued,expected_bindings={})
    def test_nonpass(self):
        a=make_envelope('EvaluationAttestation',{**self.b,'verdict':'inconclusive'})
        with self.assertRaisesRegex(ValueError,'not_pass'):validate_consumption(a,now=self.issued,**{**self.kw,'verified_attestation_digest':a['digest']})
