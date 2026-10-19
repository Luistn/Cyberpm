import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from types import SimpleNamespace

from cyberpm_gui import Cyberpm, PHASES
from gui_helpers import report_links


class CompleteReportTests(unittest.TestCase):
    def test_every_phase_includes_last_result_and_full_logs(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory)
            app=Cyberpm.__new__(Cyberpm)
            app.output_dir=str(base); app.stop_requested=False
            app.status=SimpleNamespace(get=lambda:'Concluído')
            app.target=SimpleNamespace(get=lambda:'example.invalid')
            app.finished_phases=set(); app.total_phases=29
            app.phase_messages={6:['FIRST_LOG']+['log']*2600+['LAST_LOG']}
            for phase, _ in PHASES:
                folder, names=app.PHASE_FILES[phase]
                path=base/folder/names[-1]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('line\n'*350+f'LAST_PHASE_{phase:02d}',encoding='utf-8')
            diagnostics=base/'ferramentas.tsv'
            diagnostics.write_text('x'*51000+'LAST_DIAGNOSTIC',encoding='utf-8')
            endpoint=base/'29_js'/'endpoints.tsv'
            endpoint.write_text('Endpoint\tArquivo\nhttps://example.invalid/api?id=1&x=2\tapp.js\n',encoding='utf-8')
            report=app.open_report(open_browser=False).read_text(encoding='utf-8')
            for phase, _ in PHASES:
                self.assertIn(f'LAST_PHASE_{phase:02d}',report)
            for marker in ('FIRST_LOG','LAST_LOG','LAST_DIAGNOSTIC'):
                self.assertIn(marker,report)
            self.assertIn('href="https://example.invalid/api?id=1&amp;x=2"',report)
            self.assertEqual(len(app.phase_data(6)[0][2].splitlines()),2)

    def test_links_escape_untrusted_html_and_never_link_scripts(self):
        result=report_links('<script>bad</script> https://example.invalid/a?x=1&y=2 javascript:bad')
        self.assertIn('&lt;script&gt;',result)
        self.assertNotIn('<script>',result)
        self.assertNotIn('href="javascript:',result)
        self.assertIn('rel="noopener noreferrer"',result)
        relative=report_links('/api/users?id=1\tapp.js',base_url='https://example.invalid')
        self.assertIn('href="https://example.invalid/api/users?id=1"',relative)

