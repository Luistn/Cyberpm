import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from update_checker import display_version

ROOT = Path(__file__).resolve().parents[1]


class LegacyUpdateBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = subprocess.run(['git', 'show', 'v1.6.4:update_checker.py'], cwd=ROOT,
                                capture_output=True, text=True)
        if source.returncode:
            raise unittest.SkipTest('Tag v1.6.4 não disponível para teste do cliente antigo')
        cls.legacy = ModuleType('legacy_updater')
        exec(compile(source.stdout, 'legacy_update_checker.py', 'exec'), cls.legacy.__dict__)

    def test_real_old_updater_accepts_and_installs_bridge(self):
        for fallback in (False, True):
            with self.subTest(fallback=fallback), tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
                base = Path(directory)
                (base / '.git').mkdir()
                (base / 'VERSION').write_text('1.6.4')
                (base / 'update_config.json').write_text(json.dumps({'auto_update': True}))

                def git_result(base, *args):
                    output = {('branch', '--show-current'): 'main\n',
                              ('remote', 'get-url', 'origin'): 'https://github.com/Luistn/Cyberpm.git',
                              ('show', 'v1.6.6:VERSION'): '1.6.6\n'}.get(args, '')
                    return SimpleNamespace(returncode=0, stdout=output, stderr='')

                page = MagicMock()
                page.__enter__.return_value.geturl.return_value = 'https://github.com/Luistn/Cyberpm/releases/tag/v1.6.6'
                responses = [OSError('API indisponível'), page] if fallback else [io.BytesIO(b'{"tag_name":"v1.6.6"}')]
                with patch.object(self.legacy, '_git', side_effect=git_result) as git, \
                        patch.object(self.legacy.urllib.request, 'urlopen', side_effect=responses), \
                        patch.object(self.legacy.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as installer, \
                        patch.object(self.legacy.os, 'execv', side_effect=SystemExit(0)) as restart:
                    with self.assertRaises(SystemExit):
                        self.legacy.check_updates(base, automatic=True)
                    self.assertTrue(any(call.args[1:] == ('fetch', '--no-tags', 'origin', 'refs/tags/v1.6.6:refs/tags/v1.6.6') for call in git.call_args_list))
                    self.assertTrue(any(call.args[1:] == ('merge', '--ff-only', 'v1.6.6') for call in git.call_args_list))
                    installer.assert_called_once()
                    self.assertEqual(restart.call_args.args[1][1], str(base / 'cyberpm'))

    def test_display_version_alias_only_applies_to_its_release(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            base = Path(directory)
            (base / 'VERSION').write_text('1.6.6')
            (base / 'version_info.json').write_text(json.dumps({'release_version': '1.6.6', 'display_version': '1.2'}))
            self.assertEqual(display_version(base), '1.2')
            (base / 'VERSION').write_text('1.6.7')
            self.assertEqual(display_version(base), '1.6.7')
            (base / 'version_info.json').write_text('invalid JSON')
            self.assertEqual(display_version(base), '1.6.7')
