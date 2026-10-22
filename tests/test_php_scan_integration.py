import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import php2shell
from cyberpm_gui import Cyberpm
from php2shell_window import WindowClient, conclusion, format_result, scan_target


class PHPScanIntegrationTests(unittest.TestCase):
    def test_detector_exports_window_entry_point(self):
        with patch('php2shell_window.open_window', return_value='fixture-window') as factory:
            self.assertEqual(php2shell.open_window('parent', 'https://example.invalid/login.php'), 'fixture-window')
        factory.assert_called_once_with('parent', 'https://example.invalid/login.php')

    def test_button_uses_new_detector_and_reuses_existing_window(self):
        app = Cyberpm.__new__(Cyberpm)
        app.root = object()
        app.target = SimpleNamespace(get=lambda: ' https://example.invalid/login.php ')
        lifted = []
        window = SimpleNamespace(winfo_exists=lambda: True, lift=lambda: lifted.append(True))
        with patch('php2shell.open_window', return_value=window) as factory:
            app.open_php2shell()
            app.open_php2shell()
        factory.assert_called_once_with(app.root, 'https://example.invalid/login.php')
        self.assertEqual(lifted, [True])

    def test_scan_uses_new_backend_and_explicit_active_option(self):
        for deep in (False, True):
            with self.subTest(deep=deep), patch('php2shell_window.scan', return_value={'verdict': 'UNKNOWN'}) as scanner:
                result = scan_target('example.invalid/login.php', threading.Event(), deep=deep)
                self.assertEqual(scanner.call_args.args, ('https://example.invalid/login.php',))
                self.assertEqual(scanner.call_args.kwargs['deep'], deep)
                self.assertTrue(scanner.call_args.kwargs['verify_tls'])
                self.assertFalse(result['partial'])

    def test_stop_deadline_and_scope_prevent_requests(self):
        stop = threading.Event()
        with patch.object(php2shell.HttpClient, 'request') as request:
            client = WindowClient('https://example.invalid/', stop, budget=0)
            self.assertIn('limite', client.request('GET', 'https://example.invalid/').error)
            client = WindowClient('https://example.invalid/', stop)
            stop.set()
            self.assertIn('interrompido', client.request('GET', 'https://example.invalid/').error)
            stop.clear()
            client = WindowClient('https://example.invalid/', stop)
            self.assertIn('fora da origem', client.request('GET', 'https://other.invalid/').error)
            request.assert_not_called()

    def test_page_paths_are_resolved_without_file_as_directory(self):
        base = 'https://example.invalid/login.php'
        self.assertEqual(php2shell._join(base, '/'), base)
        self.assertEqual(php2shell._join(base, '/index.php'), 'https://example.invalid/index.php')
        self.assertEqual(php2shell._join(base, '/?probe=1'), 'https://example.invalid/?probe=1')

    def test_result_contains_version_and_evidence(self):
        text = format_result({'target': 'https://example.invalid/', 'verdict': 'UNKNOWN',
                              'php_version': None, 'evidence': ['fixture evidence'], 'partial': True})
        self.assertIn('UNKNOWN', text)
        self.assertIn('não exposta', text)
        self.assertIn('fixture evidence', text)
        self.assertIn('parcial/inconclusiva', text)

    def test_forbidden_responses_are_explained_not_reported_as_safe(self):
        finding = {'target': 'https://example.invalid/', 'verdict': 'UNKNOWN', 'partial': True,
                   'http_responses': [{'method': 'GET', 'url': 'https://example.invalid/', 'status': 403, 'error': 'HTTP 403'}]}
        text = format_result(finding)
        self.assertTrue(text.startswith('CONCLUSÃO: INCONCLUSIVO'))
        self.assertIn('HTTP 403', text)
        self.assertIn('Não foi possível determinar', text)
        self.assertIn('Próximo passo:', text)

    def test_version_and_handler_results_remain_qualified(self):
        self.assertEqual(conclusion({'verdict': 'PATCHED'})[0], 'CORREÇÃO INDICADA PELA VERSÃO')
        self.assertEqual(conclusion({'verdict': 'PATCHED', 'partial': True})[0], 'INCONCLUSIVO')
        self.assertEqual(conclusion({'verdict': 'VULNERABLE'})[0], 'INDÍCIOS DE EXPOSIÇÃO')
        self.assertEqual(conclusion({'verdict': 'LIKELY_VULNERABLE'})[0], 'POTENCIALMENTE AFETADO')
        self.assertEqual(conclusion({'verdict': 'UNKNOWN'})[0], 'INCONCLUSIVO')

    def test_client_retains_http_status_for_summary(self):
        response = php2shell.Response(url='https://example.invalid/', status=403, error='HTTP 403')
        with patch.object(php2shell.HttpClient, 'request', return_value=response):
            client = WindowClient('https://example.invalid/', threading.Event())
            client.request('GET', 'https://example.invalid/')
        self.assertTrue(client.partial)
        self.assertEqual(client.responses[0]['status'], 403)
        self.assertEqual(conclusion({'verdict': 'PATCHED', 'http_responses': client.responses})[0], 'INCONCLUSIVO')

    def test_copy_button_writes_real_system_clipboard(self):
        import tkinter as tk
        from php2shell_window import open_window
        from system_clipboard import read_text
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        root.withdraw()
        original = tk.Toplevel

        def hidden_window(*args, **kwargs):
            window = original(*args, **kwargs)
            window.withdraw()
            return window

        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)

        try:
            with patch('tkinter.Toplevel', side_effect=hidden_window):
                window = open_window(root)
                widgets = list(descendants(window))
                output = next(item for item in widgets if isinstance(item, tk.Text) and str(item.cget('state')) == 'disabled')
                button = next(item for item in widgets if item.winfo_class() == 'TButton' and str(item.cget('text')) == 'Copiar resultados')
                for text in ('CONCLUSÃO: INCONCLUSIVO\nHTTP 403\n', 'Segundo resultado — acentuação ✓\n'):
                    output.configure(state='normal')
                    output.delete('1.0', 'end')
                    output.insert('1.0', text)
                    output.configure(state='disabled')
                    button.invoke()
                    root.update()
                    self.assertEqual(read_text(root), text)
                self.assertTrue(output.bind('<Control-c>'))
        finally:
            root.destroy()

    def test_window_builds_with_target_without_starting_scan(self):
        import tkinter as tk
        from php2shell_window import open_window
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        root.withdraw()
        original = tk.Toplevel

        def hidden_window(*args, **kwargs):
            window = original(*args, **kwargs)
            window.withdraw()
            return window

        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)

        try:
            with patch('tkinter.Toplevel', side_effect=hidden_window), patch('php2shell_window.scan_target') as scanner:
                window = open_window(root, 'https://example.invalid/login.php')
                widgets = list(descendants(window))
                self.assertTrue(any(isinstance(item, tk.Text) and item.get('1.0', 'end-1c') == 'https://example.invalid/login.php' for item in widgets))
                button_labels = {str(item.cget('text')) for item in widgets if item.winfo_class() == 'TButton'}
                self.assertTrue({'Iniciar Scan PHP', 'Parar', 'Exportar JSON', 'Copiar resultados'}.issubset(button_labels))
                scanner.assert_not_called()
        finally:
            root.destroy()
