import unittest
from skillloop.protection.mac_runtime import worker_configuration

class ContainerConfigTests(unittest.TestCase):
    def test_worker_only_sees_current_inputs_and_restricted_interfaces(self):
        c=worker_configuration(image='sha256:'+'a'*64,run_volume='run-new',socket_volume='socket-new',model_volume='model-new',runtime_uid=21002)
        h=c['HostConfig']
        self.assertEqual(h['NetworkMode'],'none');self.assertTrue(h['ReadonlyRootfs'])
        self.assertEqual(h['CapDrop'],['ALL']);self.assertIn('no-new-privileges',h['SecurityOpt'])
        self.assertEqual({m['Source'] for m in h['Mounts']},{'run-new','socket-new','model-new'})
        self.assertTrue(all(m['ReadOnly'] for m in h['Mounts'] if m['Target']!='/evidence'))
        self.assertNotIn('docker.sock',str(c));self.assertNotIn('authority',str(c))
    def test_image_must_be_immutable(self):
        with self.assertRaisesRegex(ValueError,'immutable_runtime_image_required'):
            worker_configuration(image='latest',run_volume='r',socket_volume='s',model_volume='m',runtime_uid=21002)
