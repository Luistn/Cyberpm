import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pentest_gui import CyberOps
from update_checker import install_release, check_updates


class ReleaseAndReportTests(unittest.TestCase):
    def test_report_contains_api_port_and_login_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory)
            for folder,name,content in (
                ('06_api','api_resultados.tsv','API_FIXTURE\tGET\t200\t12\tapplication/json'),
                ('02_portas','port_review.txt','PORT_FIXTURE 443/tcp open https'),
                ('20_brute','login_resultados.json','[{"result":"LOGIN_FIXTURE"}]')):
                (base/folder).mkdir(exist_ok=True)
                (base/folder/name).write_text(content)
            app=CyberOps.__new__(CyberOps)
            app.output_dir=str(base); app.stop_requested=False
            app.status=SimpleNamespace(get=lambda:'Concluído'); app.target=SimpleNamespace(get=lambda:'example.invalid')
            app.finished_phases={2,7}; app.total_phases=2; app.phase_messages={}
            result=app.open_report(open_browser=False)
            content=result.read_text(encoding='utf-8')
            for marker in ('API_FIXTURE','PORT_FIXTURE','LOGIN_FIXTURE'):
                self.assertIn(marker,content)

    def test_updater_rejects_dirty_installation(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory); (base/'.git').mkdir()
            responses=[SimpleNamespace(returncode=0,stdout='main\n'),SimpleNamespace(returncode=0,stdout=' M source.py\n')]
            with patch('update_checker._git',side_effect=responses) as git:
                self.assertFalse(install_release(base,'v1.2.0'))
                self.assertEqual(git.call_count,2)

    def test_updater_rejects_nonofficial_remote(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory); (base/'.git').mkdir()
            responses=[SimpleNamespace(returncode=0,stdout='main\n'),SimpleNamespace(returncode=0,stdout=''),
                       SimpleNamespace(returncode=0,stdout='https://example.invalid/repo.git')]
            with patch('update_checker._git',side_effect=responses):
                self.assertFalse(install_release(base,'v1.2.0'))

    def test_automatic_update_restarts_launcher(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory)
            (base/'VERSION').write_text('1.1.5')
            (base/'update_config.json').write_text(json.dumps({'github_repo':'Luistn/Pentest-cyberops','auto_update':True}))
            import io
            response=io.BytesIO(b'{"tag_name":"v1.2.0"}')
            with patch('update_checker.urllib.request.urlopen',return_value=response), \
                    patch('update_checker.install_release',return_value=True) as install, \
                    patch('update_checker.os.execv',side_effect=SystemExit(0)) as restart:
                with self.assertRaises(SystemExit): check_updates(base)
                install.assert_called_once_with(base,'v1.2.0')
                self.assertEqual(restart.call_args.args[1][1],str(base/'cyberops'))


if __name__ == '__main__':
    unittest.main()
