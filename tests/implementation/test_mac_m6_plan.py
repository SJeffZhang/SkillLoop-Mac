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

    def test_mac_plan_binds_its_own_isolation_profile(self):
        from pathlib import Path
        from skillloop.protocol import digest_bytes
        compiled=compile_dev_suite('orders_total');compiled['subject_digest']='sha256:'+'1'*64
        profile=Path(__file__).resolve().parents[2]/'specs/mac/runtime-profile.json'
        plan=execution_plan(compiled,campaign='mac-profile',runtime_profile_path=profile)
        self.assertEqual(plan['body']['runtime_profile_digest'],digest_bytes(profile.read_bytes()))

    def test_mac_gate_refuses_missing_pinned_isolation_inputs(self):
        import json,tempfile
        from pathlib import Path
        from scripts.dgx_m6_gate import _gate
        config={'gateway_backend':'ollama','model_id':'qwen3.8:27b-mxfp8'}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);baseline=root/'baseline';baseline.mkdir()
            (root/'manifest.json').write_text(json.dumps({'config':config,'source_index':{},'baseline_gate_digest':'baseline'}))
            (baseline/'m5b-gate.json').write_text(json.dumps({'digest':'baseline'}))
            with self.assertRaisesRegex(ValueError,'mac_gate_requires_pinned_tokenizer_and_runtime_profile'):
                _gate(root,baseline=baseline,scan_index=root/'missing',expected_config=config)

    def test_capacity_probe_binds_mac_configuration(self):
        from pathlib import Path
        from scripts.dgx_m6_calibrate import probe_suite
        root=Path(__file__).resolve().parents[2]
        config={**CONFIG,'config_id':'mac-capacity-test','gateway_backend':'ollama'}
        compiled,inputs,plan=probe_suite('orders_total',__import__('skillloop.families.registry',fromlist=['FAMILY_SPEC']).FAMILY_SPEC/'redteam',runtime_config=config,runtime_profile_path=root/'specs/mac/runtime-profile.json')
        self.assertEqual(plan['body']['config_digest'],digest_jcs(config))
        self.assertEqual(plan['body']['reserved_rollouts'],2)

    def test_mac_calibration_requires_explicit_pins(self):
        from pathlib import Path
        from scripts.dgx_m6_admit import verify_calibration
        with self.assertRaisesRegex(ValueError,'mac_calibration_requires_pinned_inputs'):
            verify_calibration(Path('/missing'),Path('/missing'),expected_config={'gateway_backend':'ollama'})

class SupplementalPrepareTests(unittest.TestCase):
    def test_invalid_profile_selection_does_not_create_campaign(self):
        from pathlib import Path
        import tempfile
        from scripts.mac_m6_prepare import prepare
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/"new"
            with self.assertRaisesRegex(ValueError, "supplemental_profile_selection"):
                prepare(root, root, root, root, root, "image", 11437,
                        profiles=("unknown",), campaign_prefix="supplemental",
                        config_id="new-config", deployment_epoch="new-epoch")
            self.assertFalse(root.exists())
