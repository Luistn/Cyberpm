import unittest
from front_inventory import extract


class FrontInventoryTests(unittest.TestCase):
    def test_scripts_with_queries_modules_and_single_quotes(self):
        html = """<script src='/assets/app.js?v=1&amp;x=2'></script>
        <SCRIPT type="module" SRC="/modules/entry"></SCRIPT><script src=/app.js></script>
        <script src='https://third.invalid/tracker.js'></script>
        <script src='https://example.invalid:9000/off.js'></script>
        <script>let x = 'inline';</script>"""
        self.assertEqual(extract('https://example.invalid', html), [
            'https://example.invalid/app.js', 'https://example.invalid/assets/app.js?v=1&x=2',
            'https://example.invalid/modules/entry'])

    def test_relative_path_and_invalid_port(self):
        html = '<script src="entry.js"></script><script src="http://example.invalid:bad/a"></script>'
        self.assertEqual(extract('https://example.invalid/shop/', html), ['https://example.invalid/shop/entry.js'])
