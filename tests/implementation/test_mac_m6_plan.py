import unittest
from scripts.dgx_m6_repair import CONFIG, execution_plan
from skillloop.discovery.suite import compile_dev_suite
from skillloop.protocol import digest_jcs

class MacPlanTests(unittest.TestCase):
    def test_new_configuration_has_own_plan_identity(self):
        compiled=compile_dev_suite('orders_total')
        compiled['subject_digest']='sha256:'+'1'*64
        legacy=execution_plan(compiled,campaign='separate-config')
        config={**CONFIG,'config_id':'mac-ollama-test','model_id':'qwen3.8:27b-mxfp8'}
        mac=execution_plan(compiled,campaign='separate-config',runtime_config=config)
        self.assertEqual(legacy['body']['config_digest'],digest_jcs(CONFIG))
        self.assertEqual(mac['body']['config_digest'],digest_jcs(config))
        self.assertNotEqual(mac['digest'],legacy['digest'])
        self.assertEqual(mac['body']['items'],legacy['body']['items'])
