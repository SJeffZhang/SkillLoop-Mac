import tempfile,sqlite3,unittest
from pathlib import Path
from skillloop.proxy.store import ProxyStore,ProxyError
from skillloop.families.task_world import fixture,stamp
from skillloop.protocol import digest_jcs
from skillloop.protection.recovery import restore_authority

class RestoreTests(unittest.TestCase):
    def test_new_epoch_revokes_old_state_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source.db';target=Path(tmp)/'restored.db';store=ProxyStore(source,deployment_epoch='old')
            domain,policy,binding,request,approval,raw=fixture();store.stage_approval(domain,approval);store.activate_approval(approval['digest'],0,operation_id='activate',request_digest=digest_jcs('activate'))
            with sqlite3.connect(source) as db:before=db.execute('SELECT * FROM trust_state').fetchall()
            receipt=restore_authority(source,target,new_epoch='new')
            self.assertEqual(receipt['new_epoch'],'new');ProxyStore(target,deployment_epoch='new')
            with self.assertRaises(ProxyError):ProxyStore(target,deployment_epoch='old')
            with sqlite3.connect(source) as db:self.assertEqual(db.execute('SELECT * FROM trust_state').fetchall(),before);self.assertEqual(db.execute('SELECT state FROM approvals').fetchone()[0],'active')
            with sqlite3.connect(target) as db:self.assertEqual(db.execute('SELECT state FROM approvals').fetchone()[0],'revoked');self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
    def test_cannot_reuse_epoch_or_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source.db';target=Path(tmp)/'restore.db';ProxyStore(source,deployment_epoch='old')
            with self.assertRaisesRegex(ValueError,'fresh_epoch'):restore_authority(source,target,new_epoch='old')
            target.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):restore_authority(source,target,new_epoch='new')
            self.assertEqual(target.read_bytes(),b'keep')
