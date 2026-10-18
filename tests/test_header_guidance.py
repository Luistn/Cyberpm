import unittest
from cyberpm_gui import classification, know


class HeaderGuidanceTests(unittest.TestCase):
    def test_legacy_403_hsts_is_not_sensitive_exposure(self):
        status, reason = classification('BAIXO', 'Cabeçalhos', 'HSTS ausente na resposta HTTP 403')
        self.assertIn('INCONCLUSIVO', status)
        self.assertIn('proxy/WAF', reason)
        self.assertNotIn('conteúdo sensível', reason)
        explain, fix = know('Cabeçalhos', 'HSTS ausente na resposta HTTP 403')
        self.assertIn('HTTPS', explain)
        self.assertIn('SAMEORIGIN', fix)
        self.assertIn('includeSubDomains', fix)

    def test_redirect_is_not_access_denied(self):
        status, reason = classification('BAIXO', 'Arquivos sensíveis', 'HTTP 302')
        self.assertIn('REDIRECIONAMENTO', status)
        self.assertNotIn('ACESSO NEGADO', status)

    def test_normal_hsts_still_requires_validation(self):
        status, _ = classification('BAIXO', 'Cabeçalhos', 'HSTS ausente na resposta HTTP 200')
        self.assertIn('REQUER VALIDAÇÃO', status)
