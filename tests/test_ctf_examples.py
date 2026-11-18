from http.client import HTTPConnection
from pathlib import Path
import tempfile
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from ctf_examples import CtfExamples
from ctf_tools import generate_wordlist, save_wordlist, transform
from ctf_window import CtfWindow
from john_window import JohnWindow
from hydra_window import HydraWindow


class ExampleDataTests(unittest.TestCase):
    def test_files_reused_and_removed_on_close(self):
        example = CtfExamples()
        try:
            root = example.files()
            self.assertEqual(root, example.files())
            self.assertTrue((root/'trafego.pcap').read_bytes().startswith(b'\xd4\xc3\xb2\xa1'))
            self.assertIn(b'Comment\0CTF{comentario_png}', (root/'cartao.png').read_bytes())
            self.assertIn('caderno42', (root/'palavras.txt').read_text())
            self.assertIn('rede2026', (root/'senhas.txt').read_text())
        finally:
            example.close()
        self.assertFalse(root.exists())
        example.close()

    def test_http_examples_login_role_sql_and_xss(self):
        example = CtfExamples()
        port = example.start()
        self.assertEqual(example.start(), port)
        self.assertEqual(example.server.server_address[0], '127.0.0.1')
        connection = HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            connection.request('GET', '/admin')
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            connection.request('GET', '/admin', headers={'Cookie':'papel=admin'})
            self.assertIn(b'CTF{admin_local}', connection.getresponse().read())
            connection.request('GET', '/perfil')
            response = connection.getresponse()
            self.assertIn('papel=aluno', response.headers['Set-Cookie'])
            response.read()
            for password, expected in [('errada', b'LOGIN_INVALIDO'), ('rede2026', b'LOGIN_ACEITO')]:
                connection.request('POST', '/login', urlencode({'user':'aluno', 'pass':password}))
                self.assertEqual(connection.getresponse().read(), expected)
            connection.request('GET', '/busca?'+urlencode({'q':"' UNION SELECT flag FROM cofre -- "}))
            self.assertIn(b'CTF{sql_local}', connection.getresponse().read())
            connection.request('GET', '/xss?'+urlencode({'q':'<script>provarXSS()</script>'}))
            body = connection.getresponse().read()
            self.assertIn(b'<script>provarXSS()</script>', body)
            self.assertIn(b'CTF{xss_local}', body)
        finally:
            connection.close()
            example.close()
        self.assertIsNone(example.server)


class WordlistTests(unittest.TestCase):
    def test_deduplication_suffixes_and_case(self):
        words = generate_wordlist('rede\nrede\ncaderno', '42\n2026\n42', True)
        self.assertEqual(len(words), len(set(words)))
        self.assertIn('rede2026', words)
        self.assertIn('caderno42', words)
        self.assertIn('REDE42', words)
        self.assertEqual(generate_wordlist('rede', '', False), ['rede'])

    def test_limits_and_empty_input(self):
        for seeds, suffixes, limit in [('', '', 50000), ('x'*257, '', 50000), ('a\nb', '1\n2', 2)]:
            with self.assertRaises(ValueError):
                generate_wordlist(seeds, suffixes, False, limit)

    def test_export_and_failed_replace_preserve_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'lista.txt'
            save_wordlist(path, ['rede2026','caderno42'])
            self.assertEqual(path.read_bytes(), b'rede2026\ncaderno42\n')
            with patch('ctf_tools.os.replace', side_effect=OSError('teste')):
                with self.assertRaises(OSError):
                    save_wordlist(path,['troca'])
            self.assertEqual(path.read_bytes(), b'rede2026\ncaderno42\n')
            self.assertEqual(list(Path(directory).iterdir()), [path])


class ClassroomWindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.withdraw()
        ttk.Style(self.root).theme_use('clam')
        self.windows = []

    def tearDown(self):
        for window in self.windows:
            if window.winfo_exists():
                window.close()
        self.root.destroy()

    def create(self, kind):
        window = kind(self.root)
        window.withdraw()
        self.windows.append(window)
        return window

    def test_all_tabs_have_load_and_clear_examples(self):
        window = self.create(CtfWindow)
        self.assertEqual(sum(button.cget('text') == 'Carregar exemplo' for button in window.buttons), 8)
        for kind in ['capture','decode','file','logs','ports','web','wordlist','guide']:
            window.load_example(kind)
            self.assertIn('Exemplo carregado',window.status.get())
            window.clear_example(kind)
            self.assertEqual(window.output.get('1.0','end-1c'),'')
        self.assertEqual(window.capture.get(),'')
        self.assertEqual(window.file.get(),'')

    def test_each_conversion_example_matches_selected_operation(self):
        window = self.create(CtfWindow)
        for operation in ['Base64 → texto','Texto → Base64','Hexadecimal → texto','Texto → hexadecimal','XOR de um byte']:
            window.operation.set(operation)
            window.load_example('decode')
            result = transform(window.input_text.get('1.0','end-1c'),operation,window.key.get())
            if operation in ('Texto → Base64','Texto → hexadecimal'):
                reverse = 'Base64 → texto' if operation == 'Texto → Base64' else 'Hexadecimal → texto'
                result = transform(result,reverse)
            self.assertEqual(result,'CTF{exemplo}')

    def test_generator_exports_from_normal_gui_action(self):
        window = self.create(CtfWindow)
        window.load_example('wordlist')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'gerada.txt'
            with patch('ctf_window.filedialog.asksaveasfilename',return_value=str(path)):
                window.generate_list(save=True)
            self.assertIn('caderno42',path.read_text())
            self.assertIn(str(path),window.output.get('1.0','end'))
        style = ttk.Style(self.root)
        self.assertEqual(style.lookup('CtfRun.TButton','background'),'#4ade80')
        self.assertEqual(style.lookup('CtfRun.TButton','foreground'),'#06210f')
        self.assertEqual(style.lookup('CtfExample.TButton','background'),'#facc15')

    def test_john_and_hydra_examples_load_clear_and_close(self):
        john = self.create(JohnWindow)
        john.load_example()
        self.assertEqual(john.format_name.get(),'sha512crypt')
        self.assertTrue(Path(john.hashes.get()).is_file())
        john.clear_example()
        self.assertEqual(john.hashes.get(),'')
        self.assertIsNone(john.inputs)
        hydra = self.create(HydraWindow)
        hydra.load_example()
        self.assertEqual(hydra.service.get(),'http-post-form')
        self.assertEqual(hydra.username.get(),'aluno')
        self.assertTrue(Path(hydra.wordlist.get()).is_file())
        hydra.clear_example()
        self.assertEqual(hydra.wordlist.get(),'')
        self.assertIsNone(hydra.examples.server)


if __name__ == '__main__':
    unittest.main()
