import unittest
from types import SimpleNamespace
from connection_health import classify
from cyberpm_gui import Cyberpm


class ConnectionHealthTests(unittest.TestCase):
    def test_success_and_denial_both_demonstrate_transport(self):
        for code in ('200', '403', '405'):
            item = classify(code+'\n192.0.2.1\n0.1\n0.2\n0.4\n0.5', 0, 'https://example.invalid')
            self.assertTrue(item['web_available'])

    def test_timeout_stages_and_dns(self):
        base = 'https://example.invalid'
        self.assertEqual(classify('000\n\n0\n0\n0\n0', 6, base)['state'], 'dns_error')
        self.assertEqual(classify('000\n\n0\n0\n0\n0', 28, base)['state'], 'connection_timeout')
        self.assertEqual(classify('000\n192.0.2.1\n0.1\n0.2\n0\n0', 28, base)['state'], 'tls_timeout')
        self.assertEqual(classify('000\n192.0.2.1\n0.1\n0.2\n0.4\n0', 28, base)['state'], 'response_timeout')
        self.assertFalse(classify('', 124, base)['web_available'])

    def test_clear_log_preserves_phase_evidence(self):
        calls = []
        app = Cyberpm.__new__(Cyberpm)
        app.log = SimpleNamespace(delete=lambda *args: calls.append(args))
        app.phase_messages = {1: ['retained evidence']}
        Cyberpm.clear_log(app)
        self.assertEqual(calls, [('1.0', 'end')])
        self.assertEqual(app.phase_messages, {1: ['retained evidence']})
