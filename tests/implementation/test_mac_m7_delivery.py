import unittest
from scripts.mac_m7_matrix import delivery_action

class DeliveryTests(unittest.TestCase):
    def test_fresh_session(self):self.assertEqual(delivery_action(None,False),'dispatch')
    def test_spent_delivery_recovery_only(self):
        for state in ('delivered','unknown','complete'):
            self.assertEqual(delivery_action((state,None),True),'recover')
    def test_uncertain_without_spending_cannot_dispatch(self):
        with self.assertRaisesRegex(ValueError,'recover_only'):delivery_action(('delivered',None),False)
    def test_unbound_spending_rejected(self):
        with self.assertRaisesRegex(ValueError,'unbound'):delivery_action(None,True)
