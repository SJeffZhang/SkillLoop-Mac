"""Contract negatives for independently authenticated family providers."""
import copy
import unittest
from skillloop.families.registry import FamilyRegistry
from skillloop.families.service import family_output,plugin_manifest,validate_output
from skillloop.protocol import ProtocolError,validate_envelope
class FamilyServiceContractTests(unittest.TestCase):
 def setUp(self):self.registry=FamilyRegistry()
 def test_table_shared_operation_and_profile_identity(self):
  x=family_output(self.registry,'table-report');self.assertEqual([p['profile_id'] for p in x['capability']['profiles']],['orders_total','refunds_total']);self.assertEqual({p['transform_id'] for p in x['capability']['profiles']},{'group_sum_join'});validate_envelope(x['manifest']);validate_output(x,x)
 def test_markdown_separate_family(self):
  x=family_output(self.registry,'markdown-index');self.assertEqual([p['profile_id'] for p in x['capability']['profiles']],['markdown_index']);self.assertEqual(x['manifest']['body']['trusted_role'],'registry')
 def test_tampered_capabilities_and_roles_rejected(self):
  x=family_output(self.registry,'table-report')
  for key in ('implementation_digest','roles_declared','profiles','build_args_schema_digest'):
   y=copy.deepcopy(x);y['capability'][key]=None
   with self.subTest(key=key),self.assertRaises(ProtocolError):validate_output(y,x)
 def test_unknown_family_and_extra_output_rejected(self):
  with self.assertRaises(ProtocolError):family_output(self.registry,'other')
  x=family_output(self.registry,'table-report');y={**x,'actor':'registry'}
  with self.assertRaises(ProtocolError):validate_output(y,x)
 def test_manifest_unknown_fields_and_digest_rejected(self):
  x=family_output(self.registry,'table-report')
  for mutation in ('extra','digest'):
   y=copy.deepcopy(x)
   if mutation=='extra':y['manifest']['body']['extra']=True
   else:y['manifest']['digest']='sha256:'+'0'*64
   with self.subTest(mutation=mutation),self.assertRaises(ProtocolError):validate_output(y,x)
if __name__=='__main__':unittest.main()
