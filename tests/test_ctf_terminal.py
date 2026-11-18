from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch

from ctf_help import (HoverTip, TOOL_GUIDES, conversion_script, hydra_terminal,
                      john_terminal, logs_script, show_document, wordlist_script)
from ctf_tools import nmap_command
from ctf_window import CtfWindow
from john_window import JohnWindow
from hydra_window import HydraWindow


def run_exported(script, directory):
    lines = script.splitlines()
    if lines[0] != "python3 - <<'PY_CTF'" or lines[-1] != 'PY_CTF':
        raise AssertionError('Invalid terminal wrapper')
    return subprocess.run([sys.executable, '-X', 'utf8', '-c', '\n'.join(lines[1:-1])],
                          cwd=directory, text=True, encoding='utf-8', capture_output=True, timeout=10)


class TerminalCodeTests(unittest.TestCase):
    def test_conversions_run_without_cyberpm_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            cases = [('Q1RGe2V4ZW1wbG99','Base64 → texto'),
                     ('43 54 46 7b 65 78 65 6d 70 6c 6f 7d','Hexadecimal → texto'),
                     ('69 7e 6c 51 4f 52 4f 47 5a 46 45 57','XOR de um byte')]
            for text, operation in cases:
                result = run_exported(conversion_script(text,operation,'2a'),directory)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout.strip(),'CTF{exemplo}')
            result = run_exported(conversion_script("a'\nPY_CTF\n$(touch arquivo)",'Texto → Base64','2a'),directory)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((Path(directory)/'arquivo').exists())

    def test_logs_and_wordlists_run_standalone(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"acesso com 'aspas'.log"
            path.write_text('01 FAIL ip=192.0.2.10 user=aluno\n02 OK ip=192.0.2.10 user=aluno\n')
            result = run_exported(logs_script(str(path),'user=aluno'),directory)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('FAIL=1 OK=1',result.stdout)
            result = run_exported(wordlist_script('rede\ncaderno','42\n2026',True),directory)
            self.assertEqual(result.returncode,0,result.stderr)
            words = (Path(directory)/'lista-ctf.txt').read_text().splitlines()
            self.assertIn('rede2026',words)
            self.assertIn('caderno42',words)
            self.assertEqual(len(words),len(set(words)))

    def test_john_hydra_and_nmap_arguments_are_shell_quoted(self):
        commands = john_terminal("/tmp/hash's file", '/tmp/word list','sha512crypt').splitlines()
        self.assertIn("/tmp/hash's file",shlex.split(commands[0]))
        self.assertIn('--wordlist=/tmp/word list',shlex.split(commands[0]))
        self.assertIn('--show',shlex.split(commands[1]))
        text = hydra_terminal('127.0.0.1','http-post-form','aluno','/tmp/list a',
                              '8765','1','1','/login:u=^USER^&p=^PASS^:F=erro',True)
        self.assertIn('/login:u=^USER^&p=^PASS^:F=erro',shlex.split(text))
        self.assertIn('/tmp/list a',shlex.split(text))
        self.assertEqual(nmap_command('::1','80,8780-8789'),
                         ['nmap','-6','-sT','-Pn','-p','80,8780-8789','::1'])


class HelpWindowTests(unittest.TestCase):
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

    def test_all_navigation_buttons_are_colored_and_select_panes(self):
        self.assertEqual(len(self.window.nav_buttons),8)
        for title,button in self.window.nav_buttons.items():
            button.invoke()
            self.assertEqual(self.window.current_tab,title)
            self.assertEqual(self.window.notebook.select(),str(self.window.tab_frames[title]))
            self.assertEqual(button.cget('foreground'),'#102031')
            self.assertTrue(button.cget('background').startswith('#'))
            self.assertIn('1.',TOOL_GUIDES[title][1])
            description,code = self.window.terminal_preview()
            self.assertTrue(description)
            self.assertTrue(code)
        self.assertEqual(len({b.cget('background') for b in self.window.nav_buttons.values()}),8)

    def test_tooltip_shows_tool_and_disappears(self):
        tip = HoverTip(self.window.nav_buttons['Capturas'],'TShark / Wireshark')
        tip.show()
        self.assertEqual(tip.popup.winfo_children()[0].cget('text'),'TShark / Wireshark')
        tip.hide()
        self.assertIsNone(tip.popup)

    def test_preview_uses_current_fields_and_never_launches_tools(self):
        with patch.object(self.window,'launch') as launch:
            self.window.select_tab('Web e sessão')
            self.window.url.set('http://127.0.0.1:8765/admin')
            self.window.cookie.set('papel=admin; token=exemplo')
            description,code = self.window.terminal_preview()
            self.assertIn('papel=admin; token=exemplo',shlex.split(code))
            self.window.select_tab('Capturas')
            self.window.capture.set('/tmp/captura com espaço.pcap')
            self.assertIn('/tmp/captura com espaço.pcap',shlex.split(self.window.terminal_preview()[1].splitlines()[0]))
        launch.assert_not_called()

    def test_code_view_copies_exact_content(self):
        dialog = show_document(self.window,'Teste','Descrição','comando com aspas')
        dialog.withdraw()
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        copy = next(widget for widget in descendants(dialog)
                    if widget.winfo_class() == 'TButton' and widget.cget('text') == 'Copiar texto')
        with patch('ctf_help.write_text') as write:
            copy.invoke()
        write.assert_called_once_with(dialog,'comando com aspas')
        dialog.destroy()

    def test_john_and_hydra_expose_help_and_terminal_view(self):
        for kind in (JohnWindow,HydraWindow):
            window = kind(self.root)
            window.withdraw()
            try:
                module = 'john_window' if kind is JohnWindow else 'hydra_window'
                with patch(module+'.show_document') as show:
                    window.show_help()
                    self.assertIn('1.',show.call_args.args[3])
                    window.show_code()
                    self.assertIn('john' if kind is JohnWindow else 'hydra',show.call_args.args[3])
            finally:
                window.close()


if __name__ == '__main__':
    unittest.main()
