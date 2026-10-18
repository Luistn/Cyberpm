import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from audit_workspace import load_contract, read_findings, save_review


class WorkspaceTests(unittest.TestCase):
    def test_review_requires_observation_and_impact(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as name:
            root=Path(name); (root/'proof.txt').write_text('evidence')
            (root/'achados.tsv').write_text('BAIXO\texample.org\tAPI\tRevisar\tproof.txt\n')
            finding=read_findings(root)[0]
            with self.assertRaises(ValueError): save_review(root,finding,'Confirmado manualmente','', 'impacto')
            with self.assertRaises(ValueError): save_review(root,finding,'Confirmado manualmente','observação', '')
            receipt=save_review(root,finding,'Confirmado manualmente','observação','impacto')
            self.assertEqual(receipt['evidence_sha256'],hashlib.sha256(b'evidence').hexdigest())
            self.assertEqual(json.loads((root/'validacao_achados.json').read_text(encoding='utf-8'))[finding['id']]['status'],'Confirmado manualmente')

    def test_contract_filters_required_and_other_origin(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as name:
            path=Path(name)/'openapi.json'
            data={'openapi':'3.0.0','info':{},'servers':[{'url':'/api'}], 'paths':{'/health':{'get':{}},'/change':{'post':{}},'/users/{id}':{'get':{}}}}
            path.write_text(json.dumps(data))
            _,urls=load_contract(path,'https://example.org')
            self.assertEqual(urls,['https://example.org/api/health'])
            data['servers']=[{'url':'https://other.example'}]; path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): load_contract(path,'https://example.org')

    def test_outside_evidence_is_not_read_or_hashed(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as name:
            root=Path(name); folder=root/'results'; folder.mkdir(); (root/'outside.txt').write_text('outside')
            finding={'id':'test','evidence':'../outside.txt'}
            result=save_review(folder,finding,'A validar','','')
            self.assertNotIn('evidence_sha256',result)
