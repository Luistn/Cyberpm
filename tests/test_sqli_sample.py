import unittest
from audit_helpers import sqli_sample


class SqliSampleTests(unittest.TestCase):
    def test_skips_assets_bare_queries_and_duplicate_shapes(self):
        base='https://example.invalid'
        urls=[base+'/app.js?v=1',base+'/a.css?v=2',base+'/file.pdf?id=1',
              base+'/page?cachekey',base+'/page?id=1',base+'/page?id=2',
              base+'/page?id=1&lang=pt','https://external.invalid/?id=1']
        sample=sqli_sample(base,urls)
        self.assertEqual(len(sample),2)
        self.assertTrue(all('/page?' in url and 'id=' in url for url in sample))

    def test_never_selects_more_than_five_routes(self):
        base='https://example.invalid'
        urls=[f'{base}/page{n}?id=1' for n in range(30)]
        self.assertEqual(len(sqli_sample(base,urls)),5)
        self.assertEqual(sqli_sample(base,urls),sqli_sample(base,list(reversed(urls))))
