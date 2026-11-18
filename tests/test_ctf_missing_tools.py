from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from ctf_help import conversion_script
from ctf_tools import http_file_report, recover_xor, replace_query
from ctf_window import CtfWindow


class AdditionalToolTests(unittest.TestCase):
    def test_http_reader_separates_status_headers_and_body(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'response.http'
            path.write_bytes(b'HTTP/1.1 200 OK\r\nX-Lab-Trace: CTF{eco_http}\r\n\r\nOK')
            result = http_file_report(path)
            self.assertIn('STATUS\nHTTP/1.1 200 OK',result)
            self.assertIn('CABEÇALHOS\nX-Lab-Trace: CTF{eco_http}',result)
            self.assertIn('CORPO DA RESPOSTA\nOK',result)
            path.write_bytes(b'not an HTTP response')
            with self.assertRaises(ValueError):
                http_file_report(path)

    def test_known_prefix_recovers_key_and_rejects_mismatch(self):
        data = '69 7e 6c 51 52 45 58 75 44 4b 75 5a 58 45 5c 4b 57'
        result = recover_xor(data,'CTF{')
        self.assertIn('Chave hexadecimal: 2a',result)
        self.assertIn('CTF{xor_na_prova}',result)
        with self.assertRaises(ValueError):
            recover_xor(data,'ERRO{')
        with self.assertRaises(ValueError):
            recover_xor('', 'CTF{')

    def test_xor_recovery_script_runs_without_program_imports(self):
        data = bytes(value^42 for value in b'CTF{exemplo}').hex(' ')
        script = conversion_script(data,'Descobrir chave XOR','00','CTF{')
        with patch('builtins.print') as printed:
            exec('\n'.join(script.splitlines()[1:-1]),{})
        self.assertIn('CTF{exemplo}',printed.call_args.args[0])

    def test_query_values_round_trip_and_other_parameters_are_preserved(self):
        for value in ["' UNION SELECT flag FROM cofre -- ",'<script>provarXSS()</script>']:
            url = replace_query('http://localhost/test?q=old&pagina=2','q',value)
            self.assertEqual(parse_qs(urlsplit(url).query),{'q':[value],'pagina':['2']})
            self.assertNotIn('<script>',url)
        with self.assertRaises(ValueError):
            replace_query('http://localhost/', '', 'x')


class AdditionalWindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.withdraw()
        self.window = CtfWindow(self.root)
        self.window.withdraw()

    def tearDown(self):
        self.window.close()
        self.root.destroy()

    def test_http_example_uses_normal_file_reader_action(self):
        self.window.load_http_example()
        self.assertTrue(Path(self.window.file.get()).is_file())
        self.window.read_http_file()
        deadline = time.monotonic()+3
        while self.window.busy and time.monotonic()<deadline:
            self.root.update()
            time.sleep(.02)
        self.assertFalse(self.window.busy)
        self.assertIn('CTF{eco_http}',self.window.output.get('1.0','end'))

    def test_url_preparation_does_not_send_request(self):
        self.window.url.set('http://localhost/xss?q=teste')
        self.window.parameter.set('q')
        self.window.parameter_value.set('<script>provarXSS()</script>')
        with patch.object(self.window,'launch') as launch:
            self.window.build_query()
        launch.assert_not_called()
        self.assertEqual(parse_qs(urlsplit(self.window.url.get()).query)['q'],['<script>provarXSS()</script>'])


if __name__=='__main__':
    unittest.main()
