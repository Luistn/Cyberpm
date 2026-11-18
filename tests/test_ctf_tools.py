import base64
from pathlib import Path
import queue
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from ctf_tools import (capture_command, file_report, host_name, log_report,
                       port_range, target_url, transform, web_command)
from ctf_window import CtfWindow
from cyberpm_gui import Cyberpm


class CtfToolsTests(unittest.TestCase):
    def test_decoding_round_trips_unicode_and_recovers_xor_flag(self):
        text = 'CTF{ação}'
        self.assertEqual(transform(transform(text, 'Texto → Base64'), 'Base64 → texto'), text)
        self.assertEqual(transform(transform(text, 'Texto → hexadecimal'), 'Hexadecimal → texto'), text)
        encrypted = bytes(value ^ 42 for value in text.encode()).hex(' ')
        self.assertEqual(transform(encrypted, 'XOR de um byte', '0x2a'), text)
        self.assertIn('ff', transform('/w==', 'Base64 → texto'))
        for operation, data, key in [('Base64 → texto', '%%%', '2a'),
                                     ('Hexadecimal → texto', 'zz', '2a'),
                                     ('XOR de um byte', '00', '100')]:
            with self.assertRaises(ValueError):
                transform(data, operation, key)

    def test_file_signature_hash_and_strings_preserve_source(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'cartao com espaço.bin'
            data = b'\x89PNG\r\n\x1a\nComment\0CTF{comentario_png}'
            source.write_bytes(data)
            result = file_report(source)
            self.assertIn('Assinatura: PNG', result)
            self.assertIn('CTF{comentario_png}', result)
            self.assertIn(hashlib.sha256(data).hexdigest(), result)
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(capture_command(source, 'Conversa TCP', stream='2')[-1],
                             'follow,tcp,ascii,2')
            args = capture_command(source, 'Resumo filtrado', 'http && tcp.port == 80')
            self.assertIn('http && tcp.port == 80', args)
            self.assertEqual(args[args.index('-r')+1], str(source.resolve()))
            with self.assertRaises(ValueError):
                capture_command(source, 'Conversa TCP', stream='-1')

    def test_log_groups_keep_accounts_separate_and_use_literal_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'acesso.log'
            path.write_text('01 FAIL ip=192.0.2.44 user=aluno\n'
                            '02 FAIL ip=192.0.2.44 user=admin\n'
                            '03 OK ip=192.0.2.44 user=aluno\n', encoding='utf-8')
            result = log_report(path, 'user=aluno')
            self.assertIn('FAIL=1 OK=1', result)
            self.assertIn('FAIL → OK', result)
            self.assertNotIn('user=admin', result)
            self.assertNotIn('FAIL=1', log_report(path, '.*'))

    def test_web_arguments_keep_session_and_url_in_single_arguments(self):
        url = 'http://127.0.0.1:8765/busca?q=Redes&pagina=1'
        for mode in ['Resposta e cabeçalhos', 'SQLmap', 'Dalfox (XSS)']:
            args = web_command(mode, url, 'papel=admin; sessao=teste')
            self.assertIn(url, args)
            self.assertIn('papel=admin; sessao=teste', args)
        self.assertEqual(target_url('http://[::1]:8765/'), 'http://[::1]:8765/')
        for url in ['file:///etc/passwd', 'http://user:pass@localhost/', 'http://localhost:bad']:
            with self.assertRaises(ValueError):
                target_url(url)
        with self.assertRaises(ValueError):
            web_command('Resposta e cabeçalhos', 'http://localhost/', 'a=b\r\nInjected: yes')

    def test_scan_input_rejects_options_and_bad_ranges(self):
        self.assertEqual(port_range('80,443,8780-8789'), '80,443,8780-8789')
        self.assertEqual(host_name('::1'), '::1')
        for value in ['0', '65536', '90-80', '80,,443', '--script=foo']:
            with self.assertRaises(ValueError):
                port_range(value)
        for value in ['--script=foo', 'localhost/path', 'two hosts']:
            with self.assertRaises(ValueError):
                host_name(value)


class CtfWindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.withdraw()
        self.app = Cyberpm.__new__(Cyberpm)
        self.app.root = self.root
        self.app.open_ctf()
        self.window = self.app.ctf_window
        self.window.withdraw()

    def tearDown(self):
        if hasattr(self, 'window') and self.window.winfo_exists():
            self.window.close()
        if hasattr(self, 'root'):
            self.root.destroy()

    def test_entry_point_reuses_window_and_conversion_finishes(self):
        self.app.open_ctf()
        self.assertIs(self.app.ctf_window, self.window)
        self.window.input_text.insert('1.0', base64.b64encode(b'CTF{teste}').decode())
        self.window.decode()
        deadline = time.monotonic() + 3
        while self.window.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.02)
        self.assertFalse(self.window.busy)
        self.assertIn('CTF{teste}', self.window.output.get('1.0', 'end'))

    def test_web_action_passes_explicit_cookie_without_echoing_it(self):
        self.window.url.set('http://127.0.0.1:8765/admin')
        self.window.cookie.set('papel=admin')
        with patch('ctf_window.shutil.which', return_value='/usr/bin/curl'), \
                patch.object(self.window, 'launch') as launch:
            self.window.external(lambda: web_command(self.window.web_mode.get(),
                                 self.window.url.get(), self.window.cookie.get()))
        self.assertIn('papel=admin', launch.call_args.args[0])
        self.assertNotIn('papel=admin', self.window.output.get('1.0', 'end'))

    def test_missing_tool_explains_installation_without_starting(self):
        with patch('ctf_window.shutil.which', return_value=None), \
                patch('ctf_window.messagebox.showerror') as error, \
                patch.object(self.window, 'launch') as launch:
            self.window.scan_ports()
        launch.assert_not_called()
        self.assertIn('nmap', error.call_args.args[1])

    def test_stop_and_failure_status_are_visible(self):
        self.window.begin()
        self.window.events.put(('log', 'erro de teste\n'))
        self.window.events.put(('done', 1))
        self.window.poll()
        self.assertFalse(self.window.busy)
        self.assertIn('Falha', self.window.status.get())
        self.window.begin()
        self.window.stop_event.set()
        self.window.events.put(('done', 1))
        self.window.poll()
        self.assertEqual(self.window.status.get(), 'Interrompido.')


if __name__ == '__main__':
    unittest.main()
