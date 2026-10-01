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
