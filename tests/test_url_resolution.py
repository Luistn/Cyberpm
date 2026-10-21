import unittest
from audit_helpers import normalize, target_origin


class UrlResolutionTests(unittest.TestCase):
    def test_page_is_not_directory(self):
        self.assertEqual(normalize('https://example.invalid/login.php',
                                   ['js/app.js', '/css/site.css']),
                         ['https://example.invalid/css/site.css',
                          'https://example.invalid/js/app.js'])

    def test_directory_and_parent_resolution(self):
        self.assertEqual(normalize('https://example.invalid/shop/',
                                   ['js/app.js', '../shared.js']),
                         ['https://example.invalid/shared.js',
                          'https://example.invalid/shop/js/app.js'])

    def test_origin_preserves_port_and_ipv6(self):
        self.assertEqual(target_origin('https://[::1]:8443/login.php?q=1'),
                         'https://[::1]:8443')

    def test_query_and_fragment_do_not_become_directory(self):
        self.assertEqual(normalize('https://example.invalid/login.php?q=1#top',
                                   ['js/app.js']),
                         ['https://example.invalid/js/app.js'])

    def test_external_references_remain_out_of_scope(self):
        self.assertEqual(normalize('https://example.invalid/login.php',
                                   ['//other.invalid/a', 'https://example.invalid:9000/a']), [])
