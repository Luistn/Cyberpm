import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cyberpm_gui import Cyberpm, ESSENTIAL, PHASES
from update_checker import install_release, check_updates


class ReleaseAndReportTests(unittest.TestCase):
    def test_phase_selection_respects_mode_unless_custom(self):
        app=Cyberpm.__new__(Cyberpm); app.custom_phases=False; app.phase_sel={20}
        app.scan_mode=SimpleNamespace(get=lambda:'Rápido')
        self.assertEqual(app.selected_phases(),ESSENTIAL)
        app.scan_mode=SimpleNamespace(get=lambda:'Completo')
        self.assertEqual(app.selected_phases(),{n for n,_ in PHASES})
        app.custom_phases=True
        self.assertEqual(app.selected_phases(),{20})

    def test_phase_failure_is_not_displayed_as_completed(self):
        states={}
        app=Cyberpm.__new__(Cyberpm); app.phase_codes={}; app.phase_rows={12:'row'}
        app.tree=SimpleNamespace(set=lambda item,column,value:states.update({item:value}))
        app.finished_phases=set(); app.total_phases=1; app.current_phase=12
        app.progress={}; app.progress_text=SimpleNamespace(set=lambda value:None)
        app.on_line('EVENT|STATUS|12|1')
        app.on_line('EVENT|END|12')
        self.assertEqual(states['row'],'Falha/parcial (1)')

    def test_findings_does_not_select_old_results_automatically(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            (Path(directory)/'cyberpm-out'/'previous.invalid').mkdir(parents=True)
            app=Cyberpm.__new__(Cyberpm); app.output_dir=None
            with patch('cyberpm_gui.ROOT',Path(directory)):
                app.sync_findings()
            self.assertIsNone(app.output_dir)

    def test_secret_refresh_clears_previous_rows_without_current_results(self):
        rows=['old secret']; details=['old detail']
        app=Cyberpm.__new__(Cyberpm); app.output_dir=None
        app.stree=SimpleNamespace(winfo_exists=lambda:True,get_children=lambda:list(rows),delete=lambda *args:rows.clear())
        app.sdetail=SimpleNamespace(winfo_exists=lambda:True,delete=lambda *args:details.clear())
        app.secret_locations={'old':'location'}
        app.secrets_refresh()
        self.assertEqual(rows,[])
        self.assertEqual(details,[])
        self.assertEqual(app.secret_locations,{})

    def test_startup_does_not_restore_previous_results(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            prefs=Path(directory)/'preferences.json'
            prefs.write_text(json.dumps({'last_output_dir':directory,'proxychains':True,'no_install':True}))
            class Variable:
                def __init__(self): self.value=False
                def set(self,value): self.value=value
                def get(self): return self.value
            app=Cyberpm.__new__(Cyberpm); app.output_dir=None
            app.use_proxychains=Variable(); app.no_install=Variable()
            with patch('cyberpm_gui.PREFS',prefs), patch('cyberpm_gui.TGCFG',Path(directory)/'missing.json'), patch('cyberpm_gui.CFG',Path(directory)):
                app.load_prefs()
                self.assertIsNone(app.output_dir)
                self.assertTrue(app.no_install.get())
                app.save_prefs()
                self.assertNotIn('last_output_dir',json.loads(prefs.read_text()))

    def test_saved_ports_identify_host_without_setting_active_target(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory); (base/'02_portas').mkdir()
            (base/'02_portas'/'portas.json').write_text(json.dumps({'host':'example.invalid','ports':[{'port':443}]}))
            captured={}
            app=Cyberpm.__new__(Cyberpm); app.output_dir=str(base)
            app.ports_btn=SimpleNamespace(configure=lambda **kwargs: captured.update(kwargs))
            app.refresh_ports()
            self.assertIn('example.invalid',captured['text'])
            self.assertIn('Portas: 1',captured['text'])
            self.assertNotIn('\n',captured['text'])
            self.assertEqual(captured['state'],'normal')
            app.output_dir=None; app.refresh_ports()
            self.assertNotIn('example.invalid',captured['text'])
            self.assertEqual(captured['state'],'disabled')

    def test_secret_location_visible_for_old_and_new_results(self):
        class Tree:
            def __init__(self): self.rows={}
            def winfo_exists(self): return True
            def get_children(self): return list(self.rows)
            def delete(self,*args): self.rows.clear()
            def insert(self,*args,values,tags):
                key=str(len(self.rows)); self.rows[key]=values; return key
            def selection(self): return ['0']
            def item(self,key,field): return self.rows[key]
        class Detail:
            def winfo_exists(self): return True
            def delete(self,*args): self.value=''
            def insert(self,*args): self.value+=args[-1]
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory); (base/'29_js').mkdir()
            app=Cyberpm.__new__(Cyberpm); app.output_dir=str(base); app.stree=Tree(); app.sdetail=Detail()
            file=base/'29_js'/'segredos.tsv'
            file.write_text('Tipo\tValor\tArquivo\nCandidato\t[VALOR OCULTO]\t29_js/arquivos/sample.js:12\n')
            app.secrets_refresh(); app.show_secret()
            self.assertIn('Linha: 12',app.sdetail.value)
            self.assertIn('sample.js',app.sdetail.value)
            file.write_text('Tipo\tValor\tArquivo\tLinha\tColuna\tURL\nCandidato\t[VALOR OCULTO]\t29_js/arquivos/sample.js\t1\t1234\thttps://example.invalid/assets/app.js\n')
            app.secrets_refresh(); app.show_secret()
            self.assertIn('Coluna: 1234',app.sdetail.value)
            self.assertIn('https://example.invalid/assets/app.js',app.sdetail.value)

    def test_closed_secret_window_is_not_refreshed(self):
        app=Cyberpm.__new__(Cyberpm)
        app.output_dir='unused'
        app.stree=SimpleNamespace(winfo_exists=lambda:False)
        app.secrets_refresh()
        app.show_secret()

    def test_report_contains_api_port_and_login_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            base=Path(directory)
            for folder,name,content in (
                ('06_api','api_resultados.tsv','API_FIXTURE\tGET\t200\t12\tapplication/json'),
                ('02_portas','port_review.txt','PORT_FIXTURE 443/tcp open https'),
                ('20_brute','login_resultados.json','[{"result":"LOGIN_FIXTURE"}]')):
                (base/folder).mkdir(exist_ok=True)
                (base/folder/name).write_text(content)
            app=Cyberpm.__new__(Cyberpm)
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
            (base/'update_config.json').write_text(json.dumps({'github_repo':'Luistn/Cyberpm','auto_update':True}))
            import io
            response=io.BytesIO(b'{"tag_name":"v1.2.0"}')
            with patch('update_checker.urllib.request.urlopen',return_value=response), \
                    patch('update_checker.install_release',return_value=True) as install, \
                    patch('update_checker.os.execv',side_effect=SystemExit(0)) as restart:
                with self.assertRaises(SystemExit): check_updates(base)
                install.assert_called_once_with(base,'v1.2.0')
                self.assertEqual(restart.call_args.args[1][1],str(base/'cyberpm'))


if __name__ == '__main__':
    unittest.main()
