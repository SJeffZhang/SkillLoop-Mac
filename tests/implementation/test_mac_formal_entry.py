import unittest
from skillloop.runtime.mac_entry import verify_formal_entry
from skillloop.protocol import digest_jcs

class FormalEntryTests(unittest.TestCase):
    def test_changed_payload_is_rejected_before_execution(self):
        value={'profile':'orders_total','digest':'sha256:'+'0'*64}
        with self.assertRaisesRegex(ValueError,'formal_entry_digest'):
            verify_formal_entry(value,image='image',source_digest='source',model_port=11435)
    def test_source_identity_is_required(self):
        value={'config':{'mac_runtime_image':'image','model_service_port':11435},'source_index_digest':'other'}
        value['digest']=digest_jcs(value)
        with self.assertRaisesRegex(ValueError,'formal_source_identity'):
            verify_formal_entry(value,image='image',source_digest='source',model_port=11435)
