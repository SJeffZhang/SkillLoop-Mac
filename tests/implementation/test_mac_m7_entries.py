import os,unittest
from pathlib import Path
from skillloop.discovery.suite import compile_dev_suite
from skillloop.protection.suite import compile_private,protected_plan
from scripts.spec_v22_families import generate_private_suite
from skillloop.protocol import digest_jcs,digest_bytes
from scripts.mac_m7_prepare import build_entries
from skillloop.runtime.mac_entry import verify_protected_entry

class Count:
    def count_text(self,text):return len(text)//3

class PrivateEntriesTests(unittest.TestCase):
    def test_twenty_four_paired_items_bind_private_bytes(self):
        bundle=generate_private_suite('orders_total',os.urandom(32));compiled=compile_private(bundle,Count(),compile_dev_suite('orders_total'))
        config={'config_id':'private','mac_runtime_image':'image','model_service_port':11436,'deployment_epoch':'private','worker_deadline_seconds':265}
        subjects={role:{'subject_digest':digest_jcs(role),'skill_digest':digest_jcs('skill'),'skill_root':'/synthetic'} for role in ('submitted','finalist')}
        plan=protected_plan(compiled,subjects,'campaign',config,runtime_profile_path=Path('specs/mac/runtime-profile.json'))
        entries=build_entries(compiled,bundle,plan,subjects,config,campaign='campaign',source_digest='source',factory_digest='factory',lifecycle_digest='lifecycle',development_epoch='dev')
        self.assertEqual(len(entries),24);self.assertEqual(len({e['entry_id'] for e in entries}),24)
        for e in entries:verify_protected_entry(e,image='image',source_digest='source',model_port=11436)
        self.assertEqual({e['role'] for e in entries},{'submitted','finalist'})
