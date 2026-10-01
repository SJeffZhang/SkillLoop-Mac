import copy,base64,unittest
from unittest.mock import patch
from skillloop.protocol import digest_jcs,digest_bytes
from skillloop.runtime.mac_entry import verify_protected_entry,protected_options

class ProtectedEntryTests(unittest.TestCase):
    def entry(self):
        config={'mac_runtime_image':'image','model_service_port':11436,'deployment_epoch':'private-1'}
        case={'digest':'case','body':{'split':'protected','fixture_digest':digest_jcs({'inputs':{'notes':digest_bytes(b'synthetic')},'expected':digest_bytes(b'result')})}}
        compiled={'profile_id':'orders_total','subject_digest':'subject','cases':{'private-case':case},'suite':{'body':{'visibility':'private_evaluation','epoch_id':'epoch'}}}
        plan={'body':{'config_digest':digest_jcs(config),'campaign_id':'campaign','phase':'protected','items':[{'subject_digest':'subject','case_digest':'case','repetition_index':0,'subject_role':'finalist','phase':'protected','requirement':'required'}]}}
        body={'kind':'protected','config':config,'source_index_digest':'source','profile':'orders_total','role':'finalist','compiled':compiled,'plan':plan,'case_id':'private-case','repetition':0,'campaign_id':'campaign','epoch_id':'epoch','approval_factory_digest':'factory','private_inputs':{'notes':base64.b64encode(b'synthetic').decode()},'private_expected_digest':digest_bytes(b'result'),'model_lifecycle_digest':'lifecycle','development_epoch':'development'}
        return self.seal(body)
    def seal(self,d):return {**{k:v for k,v in d.items() if k!='digest'},'digest':digest_jcs({k:v for k,v in d.items() if k!='digest'})}
    def verify(self,e):
        with patch('skillloop.runtime.mac_entry.validate_plan'):
            return verify_protected_entry(e,image='image',source_digest='source',model_port=11436)
    def test_valid_private_finalist(self):
        e=self.entry();self.verify(e);o=protected_options(e);self.assertEqual(o['inputs_override'],{'notes':b'synthetic'});self.assertEqual(o['approval_factory_digest'],'factory')
    def test_development_role_cannot_protect(self):
        e=self.entry();e['role']='candidate'
        with self.assertRaisesRegex(ValueError,'protected_subject_role'):self.verify(self.seal(e))
    def test_same_deployment_rejected(self):
        e=self.entry();e['development_epoch']='private-1'
        with self.assertRaisesRegex(ValueError,'protected_lifecycle'):self.verify(self.seal(e))
    def test_changed_private_input_rejected(self):
        e=self.entry();e['private_inputs']['notes']=base64.b64encode(b'changed').decode()
        with self.assertRaisesRegex(ValueError,'private_fixture_binding'):self.verify(self.seal(e))
