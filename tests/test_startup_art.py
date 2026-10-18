import io
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs
from startup_art import ascii_art, telegram_start_text, send_telegram_start


class StartupTests(unittest.TestCase):
    def test_telegram_start_is_short_and_has_no_ascii(self):
        art=ascii_art()
        self.assertGreater(len(art.splitlines()),20)
        text=telegram_start_text('a'*253,'completo')
        self.assertLessEqual(len(text),4096)
        self.assertNotIn('<pre>',text)
        self.assertNotIn(art,text)
        self.assertIn('INÍCIO INVASÃO',text)

    def test_html_escaping(self):
        text=telegram_start_text('<target>','a&b')
        self.assertNotIn('<target>',text)
        self.assertIn('&lt;target&gt;',text)
        self.assertIn('a&amp;b',text)

    @patch('startup_art.urlopen',return_value=io.BytesIO(b'{"ok":true}'))
    def test_send_uses_short_html_without_art(self,open_url):
        self.assertTrue(send_telegram_start('fixture-token','123','example.org','completo'))
        request=open_url.call_args.args[0]
        data=parse_qs(request.data.decode())
        self.assertEqual(data['parse_mode'],['HTML'])
        self.assertNotIn('<pre>',data['text'][0])
        self.assertNotIn('fixture-token',data['text'][0])

    @patch('startup_art.urlopen',side_effect=OSError('fixture-token'))
    def test_failure_returns_false_without_exception_leak(self,open_url):
        self.assertFalse(send_telegram_start('fixture-token','123','example.org','completo'))
