import unittest
from unittest.mock import patch
import subprocess
from gui_helpers import log_tag, scoped_subdomains
from osint_tools import install_missing


class GuiHelpersTests(unittest.TestCase):
    def test_scope_and_untrusted_inventory(self):
        self.assertEqual(scoped_subdomains(['a.example.com', '*.B.example.com', 'a.example.com', 'evil-example.com', 'a.example.com.evil', 'https://a.example.com', '-x.example.com'], 'example.com'), ['a.example.com', 'b.example.com'])

    def test_log_colors(self):
        for text, tag in [('══ FASE 3', 'phase'), ('[✓] concluído', 'success'), ('[!] ausente', 'warning'), ('[ERRO] teste', 'error'), ('[ACHADO ALTO] teste', 'critical'), ('[·] ferramenta', 'info')]:
            self.assertEqual(log_tag(text), tag)

    @patch('osint_tools.availability', return_value={'dig': True, 'whois': True, 'phonenumbers': True})
    @patch('osint_tools.subprocess.run')
    def test_no_install_when_available(self, run, deps):
        self.assertEqual(install_missing('E-mail'), [])
        self.assertEqual(install_missing('Nome'), [])
        run.assert_not_called()

    @patch('osint_tools.sys.platform', 'linux')
    @patch('osint_tools.os.geteuid', return_value=1000, create=True)
    @patch('osint_tools.shutil.which', side_effect=lambda name: '/usr/bin/' + name)
    @patch('osint_tools.availability', return_value={'dig': False, 'whois': True, 'phonenumbers': True})
    @patch('osint_tools.subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'installed', ''))
    def test_installs_only_missing_package(self, run, deps, which, uid):
        result=install_missing('E-mail')
        self.assertEqual(run.call_args.args[0], ['pkexec', 'apt-get', 'install', '-y', 'dnsutils'])
        self.assertEqual(result[0]['status'], 'concluído')
        self.assertFalse(run.call_args.kwargs['shell'])
