import subprocess
import unittest
from unittest.mock import patch
from osint_tools import email_domain, run_tools


class KaliToolTests(unittest.TestCase):
    def test_rejects_option_and_shell_domains(self):
        for domain in ['-h.example', 'example.com;id', 'example..com', '$(id).com']:
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                email_domain('user@' + domain)

    @patch('osint_tools.shutil.which', return_value=None)
    def test_missing_tools(self, which):
        records = run_tools({'type': 'E-mail', 'value': 'a@example.com'})
        self.assertEqual(len(records), 5)
        self.assertTrue(all(r['status'] == 'ausente' for r in records))

    @patch('osint_tools.subprocess.run')
    @patch('osint_tools.shutil.which', side_effect=lambda tool: '/usr/bin/' + tool)
    def test_commands_and_failures(self, which, run):
        run.side_effect = [subprocess.TimeoutExpired('dig', 20)] + [subprocess.CompletedProcess([], 0, 'answer', '')] * 4
        records = run_tools({'type': 'E-mail', 'value': 'a@example.com'})
        self.assertEqual(records[0]['status'], 'tempo esgotado')
        self.assertEqual(records[-1]['status'], 'concluído')
        for call in run.call_args_list:
            self.assertFalse(call.kwargs['shell'])
            self.assertEqual(call.kwargs['timeout'], 20)
            self.assertNotIn('a@example.com', call.args[0])

    def test_unsupported_types_are_explicit(self):
        self.assertEqual(run_tools({'type': 'Placa'})[0]['status'], 'sem adaptador')
