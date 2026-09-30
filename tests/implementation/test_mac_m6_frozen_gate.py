import unittest
from scripts.mac_m6_gate import sealed

class FrozenGateTests(unittest.TestCase):
    def test_unfrozen_manifest_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'frozen_record_digest'):
            sealed({'config':{},'digest':'sha256:'+'0'*64})

    def test_submitted_snapshot_can_be_staged_from_readonly_source(self):
        import tempfile
        from pathlib import Path
        from scripts.mac_m6_prepare import stage_submitted
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';skill=source/'skills/orders-total/SKILL.md';skill.parent.mkdir(parents=True);skill.write_bytes(b'exact parent');skill.chmod(0o444)
            target=Path(directory)/'target';stage_submitted(source,target,'orders-total',b'exact parent')
            self.assertEqual((target/'skills/orders-total/SKILL.md').read_bytes(),b'exact parent')
