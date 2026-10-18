import contextlib
import io
from pathlib import Path
import runpy
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class RenameMigrationTests(unittest.TestCase):
    def test_old_restart_path_reaches_new_version(self):
        result=subprocess.run([sys.executable,str(ROOT/'cyberops'),'--versao'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'Cyberpm '+(ROOT/'VERSION').read_text().strip())

    def test_bridge_preserves_all_arguments(self):
        bridge=runpy.run_path(str(ROOT/'cyberops'))
        args=['open']
        with patch.object(sys,'argv',[str(ROOT/'cyberops'),*args]), patch('os.execv',side_effect=SystemExit(0)) as restart:
            with self.assertRaises(SystemExit): bridge['main']()
            self.assertEqual(restart.call_args.args,(sys.executable,[sys.executable,str(ROOT/'cyberpm'),*args]))

    def test_missing_new_launcher_reports_recovery(self):
        bridge=runpy.run_path(str(ROOT/'cyberops'))
        output=io.StringIO()
        with patch('pathlib.Path.is_file',return_value=False), patch('os.execv') as restart, contextlib.redirect_stderr(output):
            self.assertEqual(bridge['main'](),1)
            restart.assert_not_called()
        self.assertIn('instalar.sh',output.getvalue())
