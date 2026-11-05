import queue
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import browser_runtime
from cyberpm_gui import Cyberpm
from login_checks import classify


class BrowserRuntimeTests(unittest.TestCase):
    def test_ready_only_after_all_installation_steps_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('browser_runtime.runtime_root', return_value=root), \
                 patch('browser_runtime.runtime_python', return_value=root / 'bin/python'), \
                 patch('browser_runtime.subprocess.run', return_value=SimpleNamespace(returncode=1)):
                self.assertEqual(browser_runtime.repair_browser(), 1)
                self.assertFalse((root / '.ready').exists())
            with patch('browser_runtime.runtime_root', return_value=root), \
                 patch('browser_runtime.runtime_python', return_value=root / 'bin/python'), \
                 patch('browser_runtime.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(browser_runtime.repair_browser(), 0)
                self.assertTrue((root / '.ready').exists())
                self.assertEqual(run.call_count, 4)

    def test_missing_node_cli_has_repair_instructions(self):
        msg = browser_runtime.browser_error_message("Cannot find module '/usr/share/nodejs/playwright/cli.js'")
        self.assertIn('--reparar-navegador', msg)
        self.assertIn('antes de acessar o site', msg)

    def test_405_stops_list_and_preserves_reason(self):
        result, detail = classify(405, '')
        app = Cyberpm.__new__(Cyberpm)
        app.events = queue.Queue()
        app.brute_stop = False
        with patch('cyberpm_gui.check_login', return_value={'status': 405, 'result': result, 'detail': detail}) as check:
            app._brute_worker('https://example.org/login', 'test', ['one', 'two'], {}, None)
        self.assertEqual(check.call_count, 1)
        events = list(app.events.queue)
        self.assertIn('1/2', events[-1][1])
        self.assertIn('interrompida', events[-1][1])
        self.assertIn('POST', detail)


if __name__ == '__main__':
    unittest.main()
