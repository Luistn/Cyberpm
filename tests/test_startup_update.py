import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from update_checker import check_updates, latest_release, install_release

ROOT = Path(__file__).resolve().parents[1]


class StartupUpdateTests(unittest.TestCase):
    def test_api_accepts_two_component_release(self):
        with patch('update_checker.urllib.request.urlopen', return_value=io.BytesIO(b'{"tag_name":"v1.2"}')):
            self.assertEqual(latest_release(), 'v1.2')

    def test_numbering_restart_uses_latest_official_release(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as tmp:
            base = Path(tmp)
            (base / 'VERSION').write_text('1.6.4')
            with patch('update_checker.latest_release', return_value='v1.2'), \
                    patch('update_checker.install_release', return_value=True) as install, \
                    patch('update_checker.os.execv', side_effect=SystemExit(0)):
                with self.assertRaises(SystemExit):
                    check_updates(base, automatic=True)
                install.assert_called_once_with(base, 'v1.2')

    def test_equivalent_version_does_not_restart(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as tmp:
            base = Path(tmp)
            (base / 'VERSION').write_text('1.2')
            with patch('update_checker.latest_release', return_value='v1.2.0'), \
                    patch('update_checker.install_release') as install:
                self.assertEqual(check_updates(base, automatic=True), 0)
                install.assert_not_called()

    def test_install_requires_forward_history_for_restarted_numbering(self):
        for forward in (True, False):
            with self.subTest(forward=forward), tempfile.TemporaryDirectory(dir=ROOT / 'tests') as tmp:
                base = Path(tmp)
                (base / '.git').mkdir()

                def git_result(base, *args):
                    output = {('branch', '--show-current'): 'main\n',
                              ('remote', 'get-url', 'origin'): 'https://github.com/Luistn/Cyberpm.git',
                              ('show', 'v1.2:VERSION'): '1.2\n'}.get(args, '')
                    return SimpleNamespace(returncode=int(args[0] == 'merge-base' and not forward), stdout=output, stderr='')

                with patch('update_checker._git', side_effect=git_result) as git, \
                        patch('update_checker.subprocess.run', return_value=SimpleNamespace(returncode=0)) as installer:
                    self.assertEqual(install_release(base, 'v1.2'), forward)
                    self.assertTrue(any(call.args[1:] == ('merge-base', '--is-ancestor', 'HEAD', 'v1.2^{commit}') for call in git.call_args_list))
                    if forward:
                        self.assertTrue(any(call.args[1:] == ('merge', '--ff-only', 'v1.2') for call in git.call_args_list))
                        installer.assert_called_once()
                    else:
                        installer.assert_not_called()
                        self.assertFalse(any(call.args[1] == 'merge' for call in git.call_args_list))

    def test_default_command_updates_before_opening_without_ascii(self):
        events = []
        output = io.StringIO()
        with patch('update_checker.check_updates', side_effect=lambda *a, **kw: events.append(('update', kw))), \
                patch('subprocess.call', side_effect=lambda *a, **kw: events.append(('gui', {})) or 0), \
                patch.object(sys, 'argv', ['cyberpm']), contextlib.redirect_stdout(output):
            launcher = runpy.run_path(str(ROOT / 'cyberpm'))
            self.assertEqual(launcher['main'](), 0)
        self.assertEqual([item[0] for item in events], ['update', 'gui'])
        self.assertTrue(events[0][1]['automatic'])
        self.assertEqual(output.getvalue(), '')

    def test_api_failure_falls_back_to_official_release_page(self):
        response = SimpleNamespace(geturl=lambda: 'https://github.com/Luistn/Cyberpm/releases/tag/v1.4.5')
        from unittest.mock import MagicMock
        fallback = MagicMock()
        fallback.__enter__.return_value = response
        with patch('update_checker.urllib.request.urlopen', side_effect=[OSError('unavailable'), fallback]):
            self.assertEqual(latest_release(), 'v1.4.5')

    def test_untrusted_redirect_rejected(self):
        from unittest.mock import MagicMock
        fallback = MagicMock()
        fallback.__enter__.return_value.geturl.return_value = 'https://example.invalid/releases/tag/v1.4.5'
        with patch('update_checker.urllib.request.urlopen', side_effect=[OSError(), fallback]):
            with self.assertRaises(ValueError):
                latest_release()

    def test_cli_automatic_overrides_old_preference_and_restarts(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as tmp:
            base = Path(tmp)
            (base / 'VERSION').write_text('1.4.4')
            (base / 'update_config.json').write_text(json.dumps({'auto_update': False}))
            with patch('update_checker.latest_release', return_value='v1.4.5'), \
                    patch('update_checker.install_release', return_value=True) as install, \
                    patch('update_checker.os.execv', side_effect=SystemExit(0)):
                with self.assertRaises(SystemExit):
                    check_updates(base, automatic=True)
                install.assert_called_once_with(base, 'v1.4.5')

    def test_network_failure_visible_and_manual_update_fails(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as tmp:
            base = Path(tmp)
            (base / 'VERSION').write_text('1.4.4')
            output = io.StringIO()
            with patch('update_checker.latest_release', side_effect=OSError('fixture')), contextlib.redirect_stdout(output):
                self.assertEqual(check_updates(base, force=True), 1)
            self.assertIn('Não foi possível atualizar', output.getvalue())
