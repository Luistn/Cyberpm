import json
from pathlib import Path
import tempfile
import unittest
from cve_guidance import guidance


class CveGuidanceTests(unittest.TestCase):
    def test_specific_cve_and_lab_steps(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory); (root/'29_js').mkdir()
            data={'data':[{'file':'bundle.js','results':[{'component':'axios','version':'1.7.9','vulnerabilities':[
                {'identifiers':{'CVE':['CVE-2025-27152'],'summary':'absolute URL'},'below':'1.8.2','info':['https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6']},
                {'identifiers':{'CVE':['CVE-2025-58754'],'summary':'other issue'}}]}]}]}
            (root/'29_js'/'retire.json').write_text(json.dumps(data))
            text=guidance('CVE-2025-27152',root)
            self.assertIn('axios 1.7.9',text)
            self.assertIn('127.0.0.1:10002',text)
            self.assertIn('Exploração no alvo: não demonstrada',text)
            self.assertNotIn('other issue',text)
            self.assertIn('não contém uma reprodução específica',guidance('CVE-2025-58754',root))

    def test_missing_or_invalid_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory)
            self.assertIn('indisponível',guidance('CVE-2025-27152',root))
            (root/'29_js').mkdir(); (root/'29_js'/'retire.json').write_text('[]')
            self.assertIn('formato não reconhecido',guidance('CVE-2025-27152',root))
            self.assertEqual(guidance('no id',root),'')
