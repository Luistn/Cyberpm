import unittest
from gui_helpers import log_tag, scoped_subdomains


class GuiHelpersTests(unittest.TestCase):
    def test_scope_and_untrusted_inventory(self):
        self.assertEqual(scoped_subdomains(['a.example.com', '*.B.example.com', 'a.example.com', 'evil-example.com', 'a.example.com.evil', 'https://a.example.com', '-x.example.com'], 'example.com'), ['a.example.com', 'b.example.com'])

    def test_log_colors(self):
        for text, tag in [('══ FASE 3', 'phase'), ('[✓] concluído', 'success'), ('[!] ausente', 'warning'), ('[ERRO] teste', 'error'), ('[ACHADO ALTO] teste', 'critical'), ('[·] ferramenta', 'info')]:
            self.assertEqual(log_tag(text), tag)
