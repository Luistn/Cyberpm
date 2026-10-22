# -*- coding: utf-8 -*-
"""Testes do detector php2shell (CVE-2026-109618 / CVE-2026-109619)."""

# -*- coding: utf-8 -*-
"""Testes do detector php2shell (CVE-2026-109618 / CVE-2026-109619)."""

import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if RAIZ not in sys.path:
    sys.path.insert(0, RAIZ)

from php2shell import (  # noqa: E402
    _build_multipart, _combine, classify, parse_php_version, scan, to_rows,
)

def test_parse_banner_powered_by():
    assert parse_php_version("PHP/8.4.11") == (8, 4, 11)


def test_parse_banner_server_misto():
    assert parse_php_version("Apache/2.4.58 (Ubuntu) PHP/8.2.12") == (8, 2, 12)


def test_parse_nao_confunde_wordpress_com_php():
    assert parse_php_version("WordPress 6.8.11") is None


def test_parse_versao_php_com_espaco():
    assert parse_php_version("PHP Version 8.5.11") == (8, 5, 11)


def test_parse_vazio():
    assert parse_php_version(None, "") is None


def test_classify_abaixo_da_correcao():
    assert classify((8, 4, 11)) == "LIKELY_VULNERABLE"
    assert classify((8, 5, 11)) == "LIKELY_VULNERABLE"
    assert classify((8, 2, 34)) == "LIKELY_VULNERABLE"


def test_classify_corrigido():
    assert classify((8, 2, 35)) == "PATCHED"
    assert classify((8, 3, 36)) == "PATCHED"
    assert classify((8, 4, 27)) == "PATCHED"
    assert classify((8, 5, 12)) == "PATCHED"
    assert classify((8, 5, 13)) == "PATCHED"


def test_classify_eol():
    assert classify((7, 4, 33)) == "EOL_VULNERABLE"
    assert classify((8, 1, 33)) == "EOL_VULNERABLE"
    assert classify((5, 4, 45)) == "EOL_VULNERABLE"


def test_classify_desconhecido():
    assert classify(None) == "UNKNOWN"
    assert classify((8, 6, 0)) == "UNKNOWN"


def test_combine_escalona_com_oraculo():
    assert _combine("LIKELY_VULNERABLE", True) == "VULNERABLE"
    assert _combine("EOL_VULNERABLE", True) == "VULNERABLE"
    assert _combine("LIKELY_VULNERABLE", False) == "LIKELY_VULNERABLE"


def test_combine_patchado_nao_escalona():
    assert _combine("PATCHED", True) == "PATCHED"


def test_combine_sem_versao_com_oraculo():
    assert _combine("UNKNOWN", True) == "LIKELY_VULNERABLE"
    assert _combine("UNKNOWN", False) == "UNKNOWN"


def test_multipart_campo_antes_do_arquivo():
    body, ctype = _build_multipart({"PHP_SESSION_UPLOAD_PROGRESS": "cyberpm"},
                                   {"f": ("c.txt", b"cyberpm", "text/plain")})
    assert ctype.startswith("multipart/form-data; boundary=")
    assert body.index(b'name="PHP_SESSION_UPLOAD_PROGRESS"') < body.index(b'filename="c.txt"')
    assert body.rstrip().endswith(b"--")


def test_multipart_termina_com_boundary_final():
    body, ctype = _build_multipart({}, {})
    boundary = ctype.split("boundary=")[1].encode()
    assert body.endswith(b"--" + boundary + b"--\r\n")


def test_to_rows_estrutura():
    rows = dict(to_rows({
        "cve": ["CVE-2026-109618"], "cvss": "9.2", "severity": "critical",
        "verdict": "VULNERABLE", "php_version": "8.4.11",
        "upload_progress": {"handler_active": True}, "evidence": ["a", "b"],
    }))
    assert rows["Veredito"] == "VULNERABLE"
    assert rows["upload_progress"] == "ativo"


def test_scan_sem_rede_nao_quebra():
    finding = scan("http://127.0.0.1:59999", timeout=0.4)
    assert finding["verdict"] in ("UNKNOWN", "LIKELY_VULNERABLE")
    assert finding["module"] == "php2shell"