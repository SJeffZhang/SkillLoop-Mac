import unittest
from scripts.mac_m10_capacity import disk_admission,queue_boundaries

class CapacityTests(unittest.TestCase):
    def test_host_working_reserve(self):self.assertEqual(disk_admission(49*1024**3,20*1024**3)['admission'],'rejected')
    def test_vm_reserve(self):self.assertEqual(disk_admission(100*1024**3,5*1024**3)['admission'],'rejected')
    def test_enough_headroom(self):self.assertEqual(disk_admission(100*1024**3,10*1024**3)['admission'],'ready')
    def test_all_queue_fences(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            r=queue_boundaries(Path(tmp));self.assertEqual(r['attempt_limit_consumed'],128);self.assertEqual(r['wall_budget_consumed'],108);self.assertTrue(all(r[k] for k in ('attempt_overflow_rejected','wall_overflow_rejected','expired_clock_rejected','duplicate_after_restart_rejected','clock_reset_rejected')))
