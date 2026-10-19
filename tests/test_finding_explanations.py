import unittest
from pathlib import Path
import tempfile
from types import SimpleNamespace
from cyberpm_gui import Cyberpm, finding_explanation


class FindingExplanationTests(unittest.TestCase):
    def test_sqli_is_conditional_and_has_remediation(self):
        item = finding_explanation('MÉDIO', 'SQLi — requer validação', 'Possível SQLi em parâmetro id')
        self.assertIn('Se confirmada', item['impact'])
        self.assertIn('SQLmap', item['validate'])
        self.assertIn('Prepared statements', item['fix'])
        self.assertIn('repita', item['retest'])

    def test_403_does_not_claim_impact(self):
        item = finding_explanation('BAIXO', 'Cabeçalhos', 'HSTS ausente na resposta HTTP 403')
        self.assertIn('Nenhum impacto foi confirmado', item['impact'])
        self.assertIn('HSTS', item['validate'])

    def test_crawl_is_inventory_not_exploitable_finding(self):
        item = finding_explanation('INFORMATIVO', 'Crawl', '3 URLs mapeadas')
        self.assertIn('inventário', item['impact'])
        self.assertIn('Nenhuma correção', item['fix'])

    def test_report_has_escaped_explanations_for_each_result(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            base = Path(tmp)
            (base / 'achados.tsv').write_text('BAIXO\texample.invalid\tCabeçalhos\tHSTS ausente na resposta HTTP 403 <script>\tevidence.txt\n', encoding='utf-8')
            app = Cyberpm.__new__(Cyberpm)
            app.output_dir = str(base)
            app.stop_requested = False
            app.status = SimpleNamespace(get=lambda: 'Concluído')
            app.target = SimpleNamespace(get=lambda: 'example.invalid')
            app.finished_phases = set()
            app.total_phases = 1
            app.phase_messages = {}
            report = app.open_report(open_browser=False).read_text(encoding='utf-8')
            for title in ('O que foi encontrado', 'O que pode acontecer', 'Como validar ou reproduzir', 'Como corrigir', 'Como confirmar a correção'):
                self.assertIn(title, report)
            self.assertIn('&lt;script&gt;', report)
            self.assertNotIn('<script>', report)
