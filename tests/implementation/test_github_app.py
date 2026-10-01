import unittest

class CheckTests(unittest.TestCase):
    def test_identity_binds_sha_and_configuration(self):
        from skillloop.ci.github_app import check_identity
        a=check_identity('repo',1,'a'*40,'config-a')
        self.assertEqual(a,check_identity('repo',1,'a'*40,'config-a'))
        self.assertNotEqual(a,check_identity('repo',1,'b'*40,'config-a'))
        self.assertNotEqual(a,check_identity('repo',1,'a'*40,'config-b'))
    def test_reject_invalid_sha(self):
        from skillloop.ci.github_app import check_identity
        with self.assertRaises(ValueError):check_identity('repo',1,'bad','config')

class CompletionTests(unittest.TestCase):
    def test_stale_head_cannot_complete_check(self):
        from skillloop.ci.github_app import GitHubApp
        app=object.__new__(GitHubApp);app.repository='repo';app.app_id=1
        app.request=lambda *args: {'head':{'sha':'b'*40}}
        with self.assertRaisesRegex(ValueError,'stale_head'):
            app.complete_integration_check(1,{'head_sha':'a'*40},'config')
