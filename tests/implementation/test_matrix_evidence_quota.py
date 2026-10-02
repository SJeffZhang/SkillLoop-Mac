import tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from scripts import mac_m6_matrix as matrix
from skillloop.protocol import digest_jcs
from skillloop.repair.budget import SpendingLedger

class MatrixEvidenceQuotaTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.entry={'kind':'formal','profile':'orders_total','entry_id':'quota-new-0','case_id':'case','role':'submitted','repetition':0,'config':{'worker_deadline_seconds':265,'model_service_port':1,'mac_runtime_image':'image'}};self.entry['digest']=digest_jcs(self.entry)
  self.path=self.root/'entry.json';matrix.save(self.path,self.entry);self.ledger=SpendingLedger(self.root/'spending.json',victim_seconds=265);self.q=Mock();self.resource=Mock()
 def execute(self):return matrix.execute(self.root,self.root,self.entry,self.ledger,entry_path=self.path,resource_admission=self.resource,evidence_storage=self.q)
 def test_cli_missing_quota_configuration_for_enabled_manifest_refuses(self):
  args=SimpleNamespace(evidence_quota_plan=None,evidence_quota_state=None)
  with self.assertRaisesRegex(ValueError,'evidence_quota_arguments'):matrix.evidence_storage_from_args(args,{'config':{'evidence_quota_config':'required'}})
 def test_cli_partial_quota_arguments_refuse(self):
  args=SimpleNamespace(evidence_quota_plan=self.path,evidence_quota_state=None)
  with self.assertRaisesRegex(ValueError,'evidence_quota_arguments'):matrix.evidence_storage_from_args(args,{'config':{}})
 def test_cli_legacy_has_no_evidence_keeper(self):
  args=SimpleNamespace(evidence_quota_plan=None,evidence_quota_state=None)
  self.assertIsNone(matrix.evidence_storage_from_args(args,{'config':{}}))
 def test_keeper_precedes_consume(self):
  events=[];self.resource.reserve.side_effect=lambda e:events.append('resource');self.q.prepare.side_effect=lambda e:events.append('keeper');old=self.ledger.consume
  def consume(*args):events.append('consume');return old(*args)
  self.ledger.consume=consume
  with patch.object(matrix,'model_identity'),patch.object(matrix.subprocess,'run',return_value=Mock(returncode=1)):
   self.assertEqual(self.execute(),'controller_failed')
  self.assertEqual(events,['resource','keeper','consume']);self.q.abort_unstarted.assert_not_called();self.q.verify_and_close.assert_not_called()
 def test_prepare_failure_zero_spent_and_release_resource(self):
  self.q.prepare.side_effect=ValueError('evidence_volume_exists')
  with patch.object(matrix,'model_identity'),patch.object(matrix.subprocess,'run') as worker:
   with self.assertRaisesRegex(ValueError,'evidence_volume_exists'):self.execute()
   worker.assert_not_called()
  self.assertEqual(self.ledger.read()['victim_attempts'],0);self.resource.release.assert_called_once();self.q.abort_unstarted.assert_not_called()
 def test_consume_failure_only_unstarted_abort_no_worker(self):
  self.ledger.consume=Mock(side_effect=ValueError('budget'))
  with patch.object(matrix,'model_identity'),patch.object(matrix.subprocess,'run') as worker:
   with self.assertRaisesRegex(ValueError,'budget'):self.execute()
   worker.assert_not_called()
  self.q.abort_unstarted.assert_called_once_with(self.entry);self.resource.release.assert_called_once()
 def test_export_is_verified_before_resource_release(self):
  events=[];self.q.verify_and_close.side_effect=lambda e,t:events.append('verified');self.resource.release.side_effect=lambda e:events.append('released')
  def run(args,**kw):
   if args[:2]==['docker','cp']:
    t=matrix.result_path(self.root,self.entry);t.parent.mkdir(parents=True);t.write_text('{}')
   return Mock(returncode=0)
  with patch.object(matrix,'model_identity'),patch.object(matrix.subprocess,'run',side_effect=run):self.assertEqual(self.execute(),'exported')
  self.assertEqual(events,['verified','released']);self.q.abort_unstarted.assert_not_called()
 def test_export_verification_failure_retains_keeper_and_resource(self):
  t=matrix.result_path(self.root,self.entry);t.parent.mkdir(parents=True);t.write_text('{}');self.q.verify_and_close.side_effect=ValueError('evidence_backup_mismatch')
  with self.assertRaisesRegex(ValueError,'evidence_backup_mismatch'):self.execute()
  self.q.prepare.assert_not_called();self.resource.release.assert_not_called()
 def test_completed_restart_finishes_close_without_consume(self):
  t=matrix.result_path(self.root,self.entry);t.parent.mkdir(parents=True);t.write_text('{}');self.ledger.consume(self.entry['entry_id'],0);old=self.ledger.read()
  with patch.object(matrix.subprocess,'run') as worker:self.assertEqual(self.execute(),'retained_completed');worker.assert_not_called()
  self.q.verify_and_close.assert_called_once_with(self.entry,t.parent);self.q.prepare.assert_not_called();self.assertEqual(self.ledger.read(),old)
 def test_config_cannot_enable_quota_without_adapter(self):
  e=dict(self.entry);e['config']={**e['config'],'evidence_quota_config':'frozen-quota-v1'}
  with self.assertRaisesRegex(ValueError,'evidence_quota_adapter_required'):matrix.execute(self.root,self.root,e,self.ledger)
  self.assertEqual(self.ledger.read()['victim_attempts'],0)
 def test_spent_unknown_never_prepares_again(self):
  self.ledger.consume(self.entry['entry_id'],0)
  with patch.object(matrix.subprocess,'run',return_value=Mock(returncode=1)):self.assertEqual(self.execute(),'consumed_without_container')
  self.q.prepare.assert_not_called();self.q.verify_and_close.assert_not_called();self.q.verify_prepared.assert_called_once()

if __name__=='__main__':unittest.main()
