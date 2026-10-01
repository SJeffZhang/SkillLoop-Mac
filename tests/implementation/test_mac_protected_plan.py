import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from skillloop.protection.suite import protected_plan
from skillloop.protocol import digest_bytes,digest_jcs

class MacProtectedPlanTests(unittest.TestCase):
    def test_runtime_profile_is_explicit_and_parent_is_retained(self):
        compiled={'suite':{'digest':digest_jcs('suite')},'cases':{'private':{'digest':digest_jcs('case'),'body':{'split':'protected'}}}}
        parent={'digest':digest_jcs('parent'),'body':{'revision':2,'items':[]}}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'profile.json';path.write_bytes(b'mac isolation')
            with patch('skillloop.protection.suite.validate_plan'):
                plan=protected_plan(compiled,{'finalist':{'subject_digest':digest_jcs('subject')}},'campaign',{},parent=parent,runtime_profile_path=path)
            self.assertEqual(plan['body']['runtime_profile_digest'],digest_bytes(path.read_bytes()))
            self.assertEqual(plan['body']['parent_plan_digest'],digest_jcs('parent'));self.assertEqual(len(plan['body']['items']),3)
