import unittest
from skillloop.ci.qualification import publish_qualification
from skillloop.ci.github_app import check_identity
class FakeApp:
    repository='repo';app_id=1
    def __init__(self):self.head='a'*40;self.check={'id':7,'head_sha':self.head,'external_id':check_identity('repo',1,self.head,'config'),'app':{'id':1}};self.writes=[]
    def request(self,path,method='GET',body=None):
        if path=='/pulls/1':return {'head':{'sha':self.head}}
        if method=='PATCH':self.writes.append(body);return {**self.check,**body}
        return self.check
class Registry:
    def __init__(self):self.stale=False
    def complete(self,*args):
        if self.stale:raise ValueError('stale_generation')
        return 'receipt'
class PublishTests(unittest.TestCase):
    def setUp(self):self.app=FakeApp();self.r=Registry();self.kw={'pr':1,'check_id':7,'head_sha':'a'*40,'config_digest':'config','generation':1,'campaign':'campaign','decision':{'verdict':'inconclusive'},'summary':'Synthetic fixture; no qualification asserted.'}
    def call(self):return publish_qualification(self.app,self.r,**self.kw)
    def test_inconclusive_failure(self):self.assertEqual(self.call()['conclusion'],'failure')
    def test_contract_action(self):self.kw['decision']={'verdict':'needs_contract'};self.assertEqual(self.call()['conclusion'],'action_required')
    def test_old_head(self):
        self.app.head='b'*40
        with self.assertRaisesRegex(ValueError,'stale_head'):self.call()
        self.assertFalse(self.app.writes)
    def test_wrong_app(self):
        self.app.check['app']['id']=2
        with self.assertRaisesRegex(ValueError,'check_identity'):self.call()
        self.assertFalse(self.app.writes)
    def test_wrong_config(self):
        self.kw['config_digest']='different'
        with self.assertRaisesRegex(ValueError,'check_identity'):self.call()
        self.assertFalse(self.app.writes)
    def test_stale_generation(self):
        self.r.stale=True
        with self.assertRaisesRegex(ValueError,'stale_generation'):self.call()
        self.assertFalse(self.app.writes)
    def test_head_changes_before_patch(self):
        base=self.app.request;calls=0
        def request(path,method='GET',body=None):
            nonlocal calls
            if path=='/pulls/1':
                calls+=1
                if calls==2:self.app.head='b'*40
            return base(path,method,body)
        self.app.request=request
        with self.assertRaisesRegex(ValueError,'stale_head'):self.call()
        self.assertFalse(self.app.writes)
    def test_head_changes_after_patch_detected(self):
        base=self.app.request
        def request(path,method='GET',body=None):
            result=base(path,method,body)
            if method=='PATCH':self.app.head='b'*40
            return result
        self.app.request=request
        with self.assertRaisesRegex(ValueError,'stale_head'):self.call()
        self.assertEqual(len(self.app.writes),1)
    def test_mismatched_completion_detected(self):
        base=self.app.request
        def request(path,method='GET',body=None):
            result=base(path,method,body)
            return {**result,'conclusion':'neutral'} if method=='PATCH' else result
        self.app.request=request
        with self.assertRaisesRegex(ValueError,'check_completion'):self.call()
