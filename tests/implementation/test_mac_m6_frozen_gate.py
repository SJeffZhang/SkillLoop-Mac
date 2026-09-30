import unittest
from scripts.mac_m6_gate import sealed

class FrozenGateTests(unittest.TestCase):
    def test_unfrozen_manifest_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'frozen_record_digest'):
            sealed({'config':{},'digest':'sha256:'+'0'*64})
