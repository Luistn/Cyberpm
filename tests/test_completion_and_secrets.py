import csv
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cyberpm_gui import Cyberpm
from gui_helpers import secret_rows
from sensitive_audit import main as audit_main


class CompletionAndSecretsTests(unittest.TestCase):
    def test_completion_distinguishes_partial_scan_from_process_failure(self):
        for code, finished, stopped, expected in (
            (0, False, False, 'Executado'),
            (1, True, False, 'Executado com ressalvas'),
            (1, False, False, 'Erro (1)'),
            (137, True, False, 'Erro (137)'),
            (-15, False, True, 'Interrompido'),
        ):
            with self.subTest(code=code, finished=finished, stopped=stopped):
                labels, notifications = [], []
                app = Cyberpm.__new__(Cyberpm)
                app.running = True
                app.start_btn = app.stop_btn = app.status_chip = app.report_btn = SimpleNamespace(configure=lambda **kw: None)
                app.status = SimpleNamespace(set=labels.append)
                app.log = SimpleNamespace(see=lambda *args: None)
                app.refresh_ports = app.sync_findings = app.secrets_refresh = lambda: None
                app.open_report = lambda **kwargs: Path('fixture-report.html')
                app.send_report_telegram = lambda path: None
                app.append_log = lambda message: None
                app.notify_finished = lambda title, detail, **kwargs: notifications.append(title)
                app.phase_rows = {}
                app.current_phase = None
                app.stop_requested = stopped
                if finished:
                    app.on_line('EVENT|FINISH|1')
                app.on_done(code)
                self.assertEqual(labels, [expected])
                self.assertEqual(len(notifications), 1)
                self.assertFalse(app.running)

    def test_phase_end_refreshes_secret_panel_before_scan_finishes(self):
        app = Cyberpm.__new__(Cyberpm)
        app.phase_rows = {}
        app.phase_codes = {}
        app.finished_phases = set()
        app.total_phases = 2
        app.progress = {}
        app.progress_text = SimpleNamespace(set=lambda text: None)
        refreshed = []
        app.secrets_refresh = lambda: refreshed.append(True)
        app.on_line('EVENT|END|6')
        app.on_line('EVENT|END|27')
        self.assertEqual(len(refreshed), 2)

    def test_csv_values_and_identifier_inventory_are_visible(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root = Path(directory)
            (root / '29_js').mkdir()
            (root / '18_ident').mkdir()
            value = 'fixture\twith "quotes"\nand newline'
            with (root / '29_js/segredos.tsv').open('w', encoding='utf-8', newline='') as stream:
                writer = csv.writer(stream, delimiter='\t')
                writer.writerow(['Tipo', 'Valor', 'Arquivo', 'Linha', 'Coluna', 'URL de origem'])
                writer.writerow(['Candidato', value, '29_js/arquivos/app.js', '2', '40', 'https://example.invalid/app.js'])
            with (root / '18_ident/dados_sensiveis_mascarados.tsv').open('w', encoding='utf-8', newline='') as stream:
                writer = csv.writer(stream, delimiter='\t')
                writer.writerow(['Tipo', 'Arquivo', 'Linha', 'Coluna', 'Valor'])
                writer.writerow(['Candidato', '29_js/arquivos/app.js', '2', '40', value])
                writer.writerow(['E-mail', '08_codigo/index.html', '1', '5', 'fixture@example.invalid'])
            rows = secret_rows(root)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['value'], value)
            self.assertEqual(rows[0]['column'], '40')
            self.assertEqual(rows[1]['value'], 'fixture@example.invalid')

    def test_detection_export_and_secret_detail_round_trip(self):
        class Tree:
            def __init__(self): self.rows = {}
            def winfo_exists(self): return True
            def get_children(self): return list(self.rows)
            def delete(self, *args): self.rows.clear()
            def insert(self, *args, values, tags=()):
                key = str(len(self.rows)); self.rows[key] = values; return key
            def selection(self): return ['0']
            def item(self, key, field): return self.rows[key]

        class Detail:
            def winfo_exists(self): return True
            def delete(self, *args): self.value = ''
            def insert(self, *args): self.value += args[-1]

        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root = Path(directory)
            (root / '08_codigo').mkdir()
            (root / '29_js/arquivos').mkdir(parents=True)
            (root / '08_codigo/index.html').write_text('<script>password="fixture-visible-password";</script>')
            with patch('sys.argv', ['sensitive_audit.py', '--out', str(root), '--js-only']):
                self.assertEqual(audit_main(), 0)
            app = Cyberpm.__new__(Cyberpm)
            app.output_dir = str(root)
            app.stree, app.sdetail = Tree(), Detail()
            app.secrets_refresh()
            self.assertEqual(len(app.stree.rows), 1)
            app.show_secret()
            self.assertIn('Valor encontrado: fixture-visible-password\n', app.sdetail.value)
            self.assertIn('08_codigo', app.sdetail.value)
            self.assertIn('Linha: 1', app.sdetail.value)
