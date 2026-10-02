import json,unittest
from unittest.mock import patch,Mock
from skillloop.protocol import digest_jcs

class DockerExecReservationTests(unittest.TestCase):
 def setUp(self):
  self.entry={'entry_id':'fresh-entry','config':{}};self.entry['digest']=digest_jcs(self.entry)
  self.ident={'container':'resource-v1','image':'sha256:image','plan_digest':'sha256:plan','source_digest':'sha256:source','deployment_epoch':'new-epoch'}
  self.inspection={'Id':'a'*64,'Image':self.ident['image'],'State':{'Running':True},'Config':{'Labels':{'skillloop.role':'resource-controller','skillloop.resource-plan':self.ident['plan_digest'],'skillloop.dispatcher-source':self.ident['source_digest'],'skillloop.deployment-epoch':self.ident['deployment_epoch']}},'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none'}}
 def adapter(self):
  from skillloop.runtime.docker_exec_reservation import DockerExecResourceAdmission
  return DockerExecResourceAdmission(**self.ident)
 def invoke(self,command,**kw):
  if command[:2]==['docker','inspect']:return Mock(returncode=0,stdout=json.dumps([self.inspection]),stderr='')
  request=json.loads(kw['input']);self.assertEqual(request['entry'],self.entry)
  self.assertEqual(command,['docker','exec','-i','--user','0','a'*64,'python','/resource-client.py'])
  body={'operation':request['operation'],'entry_digest':self.entry['digest'],'plan_digest':self.ident['plan_digest'],'result':{'receipt':'actual bridge result'}};body['digest']=digest_jcs(body)
  return Mock(returncode=0,stdout=json.dumps(body),stderr='')
 def test_reserve_release_use_real_exec_with_exact_identity(self):
  with patch('subprocess.run',side_effect=self.invoke) as run:
   a=self.adapter();self.assertEqual(a.reserve(self.entry),{'receipt':'actual bridge result'});a.release(self.entry)
   self.assertEqual(run.call_count,4)
 def test_wrong_image_refuses_before_exec(self):
  self.inspection['Image']='sha256:other'
  with patch('subprocess.run',side_effect=self.invoke) as run:
   with self.assertRaisesRegex(ValueError,'resource_container_identity'):self.adapter().reserve(self.entry)
   self.assertEqual(run.call_count,1)
 def test_stopped_or_wrong_epoch_refuses(self):
  for field in ('stopped','epoch','network','readonly','source','plan'):
   with self.subTest(field=field):
    original=json.loads(json.dumps(self.inspection))
    if field=='stopped':self.inspection['State']['Running']=False
    if field=='epoch':self.inspection['Config']['Labels']['skillloop.deployment-epoch']='old'
    if field=='network':self.inspection['HostConfig']['NetworkMode']='host'
    if field=='readonly':self.inspection['HostConfig']['ReadonlyRootfs']=False
    if field=='source':self.inspection['Config']['Labels']['skillloop.dispatcher-source']='other'
    if field=='plan':self.inspection['Config']['Labels']['skillloop.resource-plan']='other'
    with patch('subprocess.run',side_effect=self.invoke):
     with self.assertRaisesRegex(ValueError,'resource_container_identity'):self.adapter().reserve(self.entry)
    self.inspection=original
 def test_entry_seal_refuses_before_inspect(self):
  self.entry['entry_id']='changed'
  with patch('subprocess.run') as run:
   with self.assertRaisesRegex(ValueError,'resource_entry_digest'):self.adapter().reserve(self.entry)
   run.assert_not_called()
 def test_nonzero_exec_propagates_without_local_success(self):
  def response(cmd,**kw):
   if cmd[:2]==['docker','inspect']:return self.invoke(cmd,**kw)
   return Mock(returncode=1,stdout='',stderr='controller refused')
  with patch('subprocess.run',side_effect=response):
   with self.assertRaisesRegex(RuntimeError,'resource_exec_failed'):self.adapter().release(self.entry)
 def test_wrong_response_binding_or_seal_refuses(self):
  for field in ('entry_digest','plan_digest','operation','digest'):
   def response(cmd,**kw):
    result=self.invoke(cmd,**kw)
    if cmd[:2]==['docker','inspect']:return result
    data=json.loads(result.stdout);data[field]='wrong'
    if field!='digest':data['digest']=digest_jcs({k:v for k,v in data.items() if k!='digest'})
    result.stdout=json.dumps(data);return result
   with self.subTest(field=field),patch('subprocess.run',side_effect=response):
    with self.assertRaisesRegex(ValueError,'resource_exec_response'):self.adapter().reserve(self.entry)
if __name__=='__main__':unittest.main()
