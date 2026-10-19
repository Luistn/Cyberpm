import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from cyberpm_gui import Cyberpm


class SkipPhaseTests(unittest.TestCase):
    def app(self):
        app=Cyberpm.__new__(Cyberpm)
        app.phase_rows={5:'row5',6:'row6'}
        app.finished_phases=set()
        app.rows={}
        app.tree=SimpleNamespace(set=lambda row,col,value: app.rows.update({row:value}))
        app.append_log=lambda text:None
        return app

    def test_running_skip_writes_only_requested_control_file(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            app=self.app(); app.running=True; app.output_dir=directory
            control=Path(directory)/'controle'; control.mkdir()
            app.skip_phase(5)
            self.assertTrue((control/'pular_5').is_file())
            self.assertFalse((control/'pular_6').exists())
            app.finished_phases.add(6)
            app.skip_phase(6)
            self.assertFalse((control/'pular_6').exists())

    def test_pending_selection_can_be_omitted_before_start(self):
        app=self.app(); app.running=False
        app.selected_phases=lambda:{5,6}
        app.skip_phase(5)
        self.assertEqual(app.phase_sel,{6})
        self.assertTrue(app.custom_phases)
