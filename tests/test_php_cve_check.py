import unittest
from email.message import Message
from unittest.mock import patch
from php_cve_check import assess_version, check_url, normalize_target, NoRedirect


class Response:
    code=200
    def __init__(self, value):
        self.headers=Message()
        if value: self.headers['X-Powered-By']=value
    def __enter__(self): return self
    def __exit__(self,*args): pass


class PHPCVETests(unittest.TestCase):
    def test_each_fixed_boundary(self):
        for minor, fixed in ((2,35),(3,36),(4,27),(5,12)):
            self.assertEqual(assess_version(f'8.{minor}.{fixed-1}')[0],'POTENCIALMENTE AFETADO')
            self.assertEqual(assess_version(f'8.{minor}.{fixed}')[0],'CORREÇÃO INDICADA PELA VERSÃO')

    def test_unknown_and_prerelease_are_inconclusive(self):
        for version in ('','8.4','8.4.27RC1','8.6.0','7.4.33'):
            self.assertEqual(assess_version(version)[0],'INCONCLUSIVO')

    def test_vendor_suffix_needs_vendor_confirmation(self):
        self.assertEqual(assess_version('8.3.6-ubuntu1')[0],'INCONCLUSIVO')

    def test_normalizes_and_rejects_bad_targets(self):
        self.assertEqual(normalize_target('example.test/page.php'),'https://example.test/page.php')
        for target in ('file:///etc/passwd','https://user:pass@example.test','https://exa mple.test','https://example.test:bad'):
            with self.assertRaises(ValueError): normalize_target(target)

    @patch('php_cve_check.urllib.request.build_opener')
    def test_head_request_no_body_and_no_cookie_evidence(self, factory):
        response=Response('PHP/8.4.26')
        response.headers['Set-Cookie']='secret'
        factory.return_value.open.return_value=response
        result=check_url('https://example.test/app.php')
        request=factory.return_value.open.call_args.args[0]
        self.assertEqual(request.method,'HEAD')
        self.assertIsNone(request.data)
        self.assertEqual(result['status'],'POTENCIALMENTE AFETADO')
        self.assertNotIn('secret',str(result))

    @patch('php_cve_check.urllib.request.build_opener')
    def test_missing_or_ambiguous_version(self, factory):
        for value in ('','PHP/8.4.26 PHP/8.4.27'):
            factory.return_value.open.return_value=Response(value)
            self.assertEqual(check_url('https://example.test')['status'],'INCONCLUSIVO')

    def test_no_redirect(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://other.test'))
