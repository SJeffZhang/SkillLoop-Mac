import tempfile,unittest
from pathlib import Path
from skillloop.repair.mac_inheritance import verify_inherited_candidate

class InheritanceTests(unittest.TestCase):
    def test_missing_application_cannot_become_mac_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                verify_inherited_candidate(Path(directory),'orders_total')
