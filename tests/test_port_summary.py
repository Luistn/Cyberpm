from pathlib import Path
import tempfile
import unittest
from port_summary import summarize


class PortSummaryTests(unittest.TestCase):
    def test_cloudflare_is_inventory_not_confirmed_vulnerability(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'scan.xml'
            path.write_text('''<nmaprun><host><ports><port protocol="tcp" portid="443">
              <state state="open"/><service name="https" product="Cloudflare http proxy"/>
              <script id="ssl-cert" output="certificate"/>
              <script id="http-headers" output="Server: cloudflare"/>
              </port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>''')
            result=summarize(path,'example.invalid')
            for text in ('443/tcp','Cloudflare','nenhuma vulnerabilidade confirmada','Como achou:', 'Correção:', 'Como reproduzir:', 'Exploração:'):
                self.assertIn(text,result)
            self.assertNotIn('REVISÃO PARCIAL',result)
            self.assertIn('REVISÃO PARCIAL',summarize(path,'example.invalid',124))

    def test_missing_and_truncated_evidence_is_inconclusive(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'scan.xml'
            self.assertIn('INCONCLUSIVO',summarize(path,'example.invalid'))
            path.write_text('<nmaprun>')
            self.assertIn('INCONCLUSIVO',summarize(path,'example.invalid'))

    def test_closed_ports_not_reported_as_open(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'scan.xml'
            path.write_text('<nmaprun><host><ports><port portid="25"><state state="closed"/></port></ports></host></nmaprun>')
            result=summarize(path,'example.invalid')
            self.assertIn('Nenhuma porta aberta registrada',result)
            self.assertIn('REVISÃO PARCIAL',result)
