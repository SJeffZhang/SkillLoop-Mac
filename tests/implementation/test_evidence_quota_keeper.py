import json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
from skillloop.protocol import digest_jcs,digest_bytes

class EvidenceQuotaKeeperTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  from skillloop.runtime.evidence_quota import EvidenceQuotaKeeper
  self.cls=EvidenceQuotaKeeper
  self.policy={'config_id':'test-quota-v1','quota_bytes':33554432,'image':'sha256:image','worker_source_digest':digest_jcs('source'),'deployment_epoch':'epoch-1','keeper_module_digest':digest_bytes(Path(__import__('skillloop.runtime.evidence_quota',fromlist=['']).__file__).read_bytes())}
  self.entry={'entry_id':'new-entry','source_index_digest':self.policy['worker_source_digest'],'config':{'evidence_quota_config':'test-quota-v1','evidence_quota_policy_digest':digest_jcs(self.policy),'deployment_epoch':'epoch-1','mac_runtime_image':'sha256:image'},'case_id':'case','role':'submitted','repetition':0};self.entry['digest']=digest_jcs(self.entry)
  self.plan={'kind':'EvidenceQuotaPlan','manifest_digest':digest_jcs('manifest'),'policy':self.policy,'entries':{self.entry['entry_id']:self.entry['digest']}};self.plan['digest']=digest_jcs(self.plan)
  self.q=self.cls(self.plan,self.root/'state')
  self.remote=patch.object(self.cls,'_remote_inventory',side_effect=lambda e:self.q._inventory(self.export_root));self.remote.start();self.addCleanup(self.remote.stop)
 def exported(self):
  out=self.root/'export';out.mkdir();self.export_root=out;(out/'result.json').write_text('{}');(out/'actual-evidence.bin').write_bytes(b'committed evidence')
  for name in ('authority.db','authority.backup.db'):
   with sqlite3.connect(out/name) as db:db.execute('CREATE TABLE observations (id INTEGER,value TEXT)');db.execute("INSERT INTO observations VALUES(1,'committed')")
  return out
 def seed_prepared(self):
  self.q._save(self.entry,{'state':'prepared','keeper_id':'a'*64,'volume':self.q.names(self.entry)[0]})
 def test_binding_rejects_changed_entry_before_docker(self):
  self.entry['entry_id']='changed'
  with patch.object(self.q,'_docker') as run:
   with self.assertRaisesRegex(ValueError,'evidence_entry_binding'):self.q.prepare(self.entry)
   run.assert_not_called()
 def test_wrong_policy_config_source_epoch_refused(self):
  for key in ('evidence_quota_policy_digest','deployment_epoch','mac_runtime_image'):
   e=json.loads(json.dumps(self.entry));e['config'][key]='wrong';e['digest']=digest_jcs({k:v for k,v in e.items() if k!='digest'})
   p=json.loads(json.dumps(self.plan));p['entries'][e['entry_id']]=e['digest'];p['digest']=digest_jcs({k:v for k,v in p.items() if k!='digest'})
   q=self.cls(p,self.root/key)
   with self.assertRaisesRegex(ValueError,'evidence_entry_binding'):q.prepare(e)
 def test_oversized_or_zero_quota_refused(self):
  for n in (0,True,536870913):
   p=json.loads(json.dumps(self.plan));p['policy']['quota_bytes']=n;p['digest']=digest_jcs({k:v for k,v in p.items() if k!='digest'})
   with self.assertRaisesRegex(ValueError,'evidence_quota_policy'):self.cls(p,self.root/str(n))
 def test_preexisting_volume_never_adopted(self):
  with patch.object(self.q,'_docker',return_value=Mock(returncode=0,stdout='[]')) as run:
   with self.assertRaisesRegex(ValueError,'evidence_volume_exists'):self.q.prepare(self.entry)
   self.assertEqual(run.call_count,1)
 def test_backup_mismatch_retains_keeper(self):
  self.seed_prepared();out=self.exported()
  with sqlite3.connect(out/'authority.backup.db') as db:db.execute("UPDATE observations SET value='different'")
  with patch.object(self.q,'verify_prepared'),patch.object(self.q,'_stop') as stop:
   with self.assertRaisesRegex(ValueError,'evidence_backup_mismatch'):self.q.verify_and_close(self.entry,out)
   stop.assert_not_called();self.assertEqual(self.q._load(self.entry)['state'],'prepared')
 def test_symlink_export_refuses_to_close(self):
  self.seed_prepared();out=self.exported();(out/'link').symlink_to(out/'result.json')
  with patch.object(self.q,'verify_prepared'),patch.object(self.q,'_stop') as stop:
   with self.assertRaisesRegex(ValueError,'evidence_export_unsafe'):self.q.verify_and_close(self.entry,out)
   stop.assert_not_called()
 def test_complete_export_sealed_before_keeper_stops(self):
  self.seed_prepared();out=self.exported();states=[]
  with patch.object(self.q,'verify_prepared'),patch.object(self.q,'_stop',side_effect=lambda e:states.append(self.q._load(e)['state'])):
   receipt=self.q.verify_and_close(self.entry,out)
  self.assertEqual(states,['export_verified']);self.assertEqual(self.q._load(self.entry)['state'],'closed');self.assertEqual(len(receipt['files']),4)
  self.assertEqual(receipt['digest'],digest_jcs({k:v for k,v in receipt.items() if k!='digest'}))
 def test_lost_stop_ack_restart_only_closes_never_prepares_again(self):
  self.seed_prepared();out=self.exported()
  with patch.object(self.q,'verify_prepared'),patch.object(self.q,'_stop',side_effect=RuntimeError('lost stop ACK')):
   with self.assertRaises(RuntimeError):self.q.verify_and_close(self.entry,out)
  self.assertEqual(self.q._load(self.entry)['state'],'export_verified')
  restart=self.cls(self.plan,self.root/'state')
  with patch.object(restart,'_stop') as stop,patch.object(restart,'prepare') as prep:
   restart.verify_and_close(self.entry,out);stop.assert_called_once();prep.assert_not_called()
 def test_closed_export_tampering_refuses_idempotent_completion(self):
  self.seed_prepared();out=self.exported()
  with patch.object(self.q,'verify_prepared'),patch.object(self.q,'_stop'):self.q.verify_and_close(self.entry,out)
  (out/'actual-evidence.bin').write_bytes(b'tamper')
  with self.assertRaisesRegex(ValueError,'evidence_export_changed'):self.q.verify_and_close(self.entry,out)
 def test_stopped_oci_inventory_mismatch_retains_keeper(self):
  self.seed_prepared();out=self.exported()
  with patch.object(self.q,'verify_prepared'),patch.object(self.q,'_remote_inventory',return_value=[]),patch.object(self.q,'_stop') as stop:
   with self.assertRaisesRegex(ValueError,'evidence_oci_export_mismatch'):self.q.verify_and_close(self.entry,out)
   stop.assert_not_called()
 def test_unstarted_abort_has_no_export_success_claim(self):
  self.seed_prepared()
  with patch.object(self.q,'_stop') as stop:self.q.abort_unstarted(self.entry);stop.assert_called_once()
  self.assertEqual(self.q._load(self.entry)['state'],'aborted_before_worker')

if __name__=='__main__':unittest.main()
