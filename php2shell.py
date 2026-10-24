#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell - Detector para CVE-2026-109618 / CVE-2026-109619
===========================================================

Modulo da fase de scan PHP do Cyberpm.

O QUE FAZ
  1. Fingerprint passivo da versao do PHP (X-Powered-By, Server, X-PHP-Version,
     PHPSESSID, easter egg do phpinfo com expose_php ligado).
  2. Compara a versao com a tabela oficial de correcoes e classifica o alvo.
  3. Oraculo leve de upload_progress (2 POSTs de ~300 bytes, diferencial).
  4. Teste ativo opcional (--active): stall multipart, micro trigger e sonda de
     fixacao de sessao. Nada disso executa codigo.
  5. Cadeia 619 opcional (--chain 619 --call 0x...), que ai sim busca RCE.
  6. Ponte opcional para o PoC externo EDB-52704 (--exploit): roda o exploit
     one-click por subprocesso e promove o veredito para RCE_CONFIRMED quando
     ha PROOF. Padrao "auto" = so roda quando ha sinal.

PROBES RELATIVOS AO DIRETORIO
  Os nomes convencionais (index.php, phpinfo.php, info.php, wp-login.php) sao
  resolvidos no MESMO diretorio da URL informada, com fallback na raiz.

O QUE NAO FAZ
  Sem --active: nenhum POST alem do oraculo leve. Sem --exploit/--chain 619:
  nenhuma execucao de codigo. O RCE real depende dos offsets do build do alvo.

REFERENCIAS
  https://vexday.io/pt/cve/CVE-2026-109618
  https://github.com/murrez/php2shell
  https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
  https://www.exploit-db.com/exploits/52704
  Corrigido em PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (21/10/2026)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urljoin, urlparse, urlunparse

__all__ = [
    "scan", "fingerprint", "check_upload_progress", "parse_php_version", "classify",
    "to_rows", "write_evidence", "run_murrez", "run_edb52704", "edb52704_available",
    "HttpClient", "MODULE_META", "open_window", "headline", "exploit_used",
]

VERSION = "1.2.0"
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
CVSS = "9.2 (CVSS v4.0)"

FIXED_TABLE: Dict[str, Tuple[int, int, int]] = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}
FIXED_TEXT = "8.2.35, 8.3.36, 8.4.27 e 8.5.12"

UPLOAD_FIELD_DEFAULT = "PHP_SESSION_UPLOAD_PROGRESS"
DEFAULT_TIMEOUT = 8.0
MAX_BODY = 262144
UA = f"Cyberpm-php2shell/{VERSION}"

MODULE_META: Dict[str, Any] = {
    "id": "php2shell",
    "name": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
    "phase": "scan_php",
    "severity_max": "critical",
    "needs_network": True,
    "fast_mode": False,
    "destructive": False,
}

PROBE_NAMES: Tuple[str, ...] = ("index.php", "phpinfo.php", "info.php", "wp-login.php")
ORACLE_NAMES: Tuple[str, ...] = ("index.php",)
HUNT_NAMES: Tuple[str, ...] = (
    "phpinfo.php", "info.php", "test.php", "php.php", "i.php", "p.php",
    "phpinfo", "server.php", "debug.php", "php_version.php", "version.php",
)
_EG_QUERY = "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

PROBE_PATHS: Tuple[str, ...] = ("/", "/index.php", "/wp-login.php", "/info.php", "/phpinfo.php")
ORACLE_PATHS: Tuple[str, ...] = ("/", "/index.php")

_RE_PHP_BANNER = re.compile(
    r"php[\s/_-]*(?:(?:version|fpm|cgi|cli|apache|module)[\s/:_-]*)?"
    r"(\d{1,2})\.(\d{1,2})\.(\d{1,3})",
    re.IGNORECASE,
)

_SEVERITY = {
    "RCE_CONFIRMED": "critical",
    "PRIMITIVE_CONFIRMED": "high",
    "CRASH_SIGNAL": "high",
    "VULNERABLE": "critical",
    "EOL_VULNERABLE": "critical",
    "LIKELY_VULNERABLE": "high",
    "PATCHED": "info",
    "UNKNOWN": "info",
}

_ACTIVE_LABEL = {
    "rce_hit": "execucao de codigo (marcador no corpo)",
    "armed": "upload_progress armado (monitor)",
    "session_fixation": "primitiva de fixacao de sessao confirmada",
    "crash_signal": "worker instavel / sem resposta",
    "upload_accepted": "POST multipart aceito (sinal fraco)",
    "inconclusive": "sem sinal forte",
    "unreachable": "sem resposta",
    "bad_args": "faltam offsets (--call)",
}

REMEDIATION = [
    f"Atualizar o PHP para {FIXED_TEXT} (ou superior na mesma branch) e reiniciar o SAPI web.",
    "Branches EOL (5.x, 7.x, 8.0, 8.1) nao tem release oficial: subir para 8.2+ ou "
    "recompilar com o patch de fonte do aviso do PHP.",
    "Mitigacao temporaria: session.upload_progress.enabled = 0 no php.ini efetivo do "
    "SAPI web (ou php_admin_flag[session.upload_progress.enabled]=off no pool FPM), com "
    "memory_limit em valor real (nao -1) e post_max_size reduzido. Reiniciar php-fpm/apache. "
    "E paliativo: nao substitui o patch.",
    "Endurecer sessao: session.use_only_cookies = On.",
    "Docker: puxar imagens oficiais reconstruidas. As tags antigas continuam vulneraveis "
    "mesmo com o framework atualizado - a falha e no runtime, nao no codigo da aplicacao.",
    "Desconfiar de backport de distro: o banner pode mentir ate voce conferir php -v / "
    "changelog do pacote na maquina.",
]

REFERENCES = [
    "https://vexday.io/pt/cve/CVE-2026-109618",
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
    "https://github.com/murrez/php2shell",
    "https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC",
    "https://github.com/ikow/php2shell-poc",
    "https://www.exploit-db.com/exploits/52704",
]


# --------------------------------------------------------------------------- #
# HTTP minimo
# --------------------------------------------------------------------------- #
@dataclass
class Response:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    set_cookies: List[str] = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def ok(self) -> bool:
        return self.status > 0


class HttpClient:
    """Cliente urllib sem cookiejar, para ver os Set-Cookie crus da resposta."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = False,
                 user_agent: str = UA) -> None:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urlrequest.build_opener(urlrequest.HTTPSHandler(context=ctx))
        self.timeout = timeout
        self.user_agent = user_agent

    def request(self, method: str, url: str, data: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None) -> Response:
        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)
        req = urlrequest.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.time()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(MAX_BODY)
                return Response(
                    url=resp.geturl(),
                    status=getattr(resp, "status", 200) or 200,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    set_cookies=list(resp.headers.get_all("Set-Cookie") or []),
                    body=body,
                    elapsed=time.time() - t0,
                )
        except urlerror.HTTPError as exc:
            body = b""
            try:
                body = exc.read(MAX_BODY)
            except Exception:
                pass
            return Response(
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                set_cookies=list((exc.headers.get_all("Set-Cookie") if exc.headers else []) or []),
                body=body,
                elapsed=time.time() - t0,
                error=f"HTTP {exc.code}",
            )
        except Exception as exc:
            return Response(url=url, status=0, elapsed=time.time() - t0,
                            error=f"{type(exc).__name__}: {exc}")

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, data: bytes, headers: Optional[Dict[str, str]] = None) -> Response:
        return self.request("POST", url, data=data, headers=headers)


# --------------------------------------------------------------------------- #
# Helpers puros (testaveis sem rede)
# --------------------------------------------------------------------------- #
def _normalize(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("URL vazia")
    if not urlparse(url).scheme:
        url = "https://" + url
    parts = urlparse(url)
    return urlunparse((parts.scheme, parts.netloc, parts.path or "/", parts.params, parts.query, ""))


def _join(base: str, path: str) -> str:
    if not path or path == "/":
        return base
    return urljoin(base, path)


def _origin(base: str) -> str:
    parts = urlparse(base)
    return f"{parts.scheme}://{parts.netloc}"


def _base_dir(base: str) -> str:
    path = urlparse(base).path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return path or "/"


def _urls_for(base: str, names: Sequence[str], *,
              fallback_root: bool = True) -> List[str]:
    origin, directory = _origin(base), _base_dir(base)
    urls: List[str] = [base]
    for name in names:
        urls.append(origin + directory + name)
    if fallback_root and directory != "/":
        for name in names:
            urls.append(origin + "/" + name)
    ordered: List[str] = []
    for url in urls:
        if url not in ordered:
            ordered.append(url)
    return ordered


def parse_php_version(*texts: Optional[str]) -> Optional[Tuple[int, int, int]]:
    for text in texts:
        if not text:
            continue
        m = _RE_PHP_BANNER.search(text)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def classify(version: Optional[Tuple[int, int, int]]) -> str:
    if not version:
        return "UNKNOWN"
    major, minor, _patch = version
    key = f"{major}.{minor}"
    if key in FIXED_TABLE:
        return "PATCHED" if version >= FIXED_TABLE[key] else "LIKELY_VULNERABLE"
    if (major, minor) < (8, 2):
        return "EOL_VULNERABLE"
    return "UNKNOWN"


def _combine(version_verdict: str, handler_active: bool) -> str:
    if version_verdict == "PATCHED":
        return "PATCHED"
    if version_verdict == "EOL_VULNERABLE":
        return "VULNERABLE" if handler_active else "EOL_VULNERABLE"
    if version_verdict == "LIKELY_VULNERABLE":
        return "VULNERABLE" if handler_active else "LIKELY_VULNERABLE"
    return "LIKELY_VULNERABLE" if handler_active else "UNKNOWN"


def _combine_active(version_verdict: str, active_status: str) -> str:
    if active_status == "rce_hit":
        return "RCE_CONFIRMED"
    if active_status in ("armed", "session_fixation"):
        return "PRIMITIVE_CONFIRMED"
    if active_status == "crash_signal":
        return "CRASH_SIGNAL" if version_verdict in ("UNKNOWN", "PATCHED") else version_verdict
    return version_verdict


def _build_multipart(fields: Dict[str, str],
                     files: Dict[str, Tuple[str, bytes, str]]) -> Tuple[bytes, str]:
    boundary = "----CyberpmPhp2Shell" + uuid.uuid4().hex
    crlf = b"\r\n"
    out = bytearray()
    for name, value in fields.items():
        out += b"--" + boundary.encode() + crlf
        out += f'Content-Disposition: form-data; name="{name}"'.encode() + crlf + crlf
        out += str(value).encode("utf-8") + crlf
    for name, (filename, content, ctype) in files.items():
        out += b"--" + boundary.encode() + crlf
        out += (f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"').encode() + crlf
        out += f"Content-Type: {ctype}".encode() + crlf + crlf
        out += content + crlf
    out += b"--" + boundary.encode() + b"--" + crlf
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def _has_session_cookie(resp: Response) -> bool:
    return any("phpsessid" in c.lower() for c in resp.set_cookies)


# --------------------------------------------------------------------------- #
# Camada 1 - fingerprint passivo
# --------------------------------------------------------------------------- #
def _easter_egg(base: str, client: HttpClient) -> Tuple[Optional[Tuple[int, int, int]], List[str]]:
    evidence: List[str] = []
    for candidate in (base, _origin(base) + "/"):
        r = client.get(_join(candidate, _EG_QUERY))
        if r.status == 200:
            version = parse_php_version(r.text)
            if version:
                evidence.append(
                    f"easter egg phpinfo em {candidate} revelou PHP "
                    f"{version[0]}.{version[1]}.{version[2]}"
                )
                return version, evidence
            if "php" in r.text.lower() and "credits" in r.text.lower():
                evidence.append(
                    f"easter egg phpinfo respondeu 200 em {candidate} (sem versao no corpo)"
                )
    return None, evidence


def fingerprint(base: str, client: HttpClient,
                paths: Optional[Sequence[str]] = None,
                use_easter_egg: bool = True) -> Tuple[Optional[Tuple[int, int, int]], bool, List[str]]:
    evidence: List[str] = []
    version: Optional[Tuple[int, int, int]] = None
    php_detected = False
    urls = _urls_for(base, PROBE_NAMES) if paths is None else [_join(base, p) for p in paths]

    for url in urls:
        r = client.get(url)
        if not r.ok:
            evidence.append(f"GET {url} -> falha ({r.error or 'sem resposta'})")
            continue
        evidence.append(f"GET {url} -> HTTP {r.status} ({r.elapsed:.2f}s)")

        for label, raw in (("X-Powered-By", r.headers.get("x-powered-by")),
                           ("Server", r.headers.get("server")),
                           ("X-PHP-Version", r.headers.get("x-php-version")),
                           ("X-Backend-Server", r.headers.get("x-backend-server"))):
            if not raw:
                continue
            found = parse_php_version(raw)
            if found and not version:
                version = found
                evidence.append(
                    f"versao PHP {found[0]}.{found[1]}.{found[2]} exposta no header "
                    f"{label}: {raw!r}"
                )
            if "php" in raw.lower():
                php_detected = True

        if _has_session_cookie(r):
            php_detected = True
            evidence.append(f"cookie de sessao PHP (PHPSESSID) emitido por {url}")

        low = r.text.lower()
        if "phpsessid" in low or "x-powered-by" in r.headers:
            php_detected = True

    if use_easter_egg and not version:
        egg_version, egg_evidence = _easter_egg(base, client)
        evidence.extend(egg_evidence)
        if egg_version:
            version = egg_version
            php_detected = True

    if not version and php_detected:
        hunt_version, hunt_evidence = _version_hunt(base, client)
        evidence.extend(hunt_evidence)
        if hunt_version:
            version = hunt_version

    return version, php_detected, evidence


# --------------------------------------------------------------------------- #
# Camada 2 - oraculo session.upload_progress
# --------------------------------------------------------------------------- #
def check_upload_progress(base: str, client: HttpClient,
                          field_name: str = UPLOAD_FIELD_DEFAULT,
                          paths: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "handler_active": False,
        "confidence": "baixa",
        "field": field_name,
        "probes": [],
        "evidence": [],
    }
    payload = "cyberpm"
    urls = (_urls_for(base, ORACLE_NAMES, fallback_root=False)
            if paths is None else [_join(base, p) for p in paths])

    for url in urls:
        ctrl_body, ctrl_ct = _build_multipart({}, {"f": ("c.txt", b"cyberpm", "text/plain")})
        ctrl = client.post(url, ctrl_body, headers={
            "Content-Type": ctrl_ct, "Content-Length": str(len(ctrl_body)),
        })

        test_body, test_ct = _build_multipart({field_name: payload},
                                              {"f": ("c.txt", b"cyberpm", "text/plain")})
        test = client.post(url, test_body, headers={
            "Content-Type": test_ct, "Content-Length": str(len(test_body)),
        })

        if not test.ok:
            result["probes"].append({"url": url, "status": test.status, "error": test.error})
            continue

        if ctrl.status in (404, 405) and test.status in (404, 405):
            result["probes"].append({"url": url, "status": test.status,
                                     "ctrl_status": ctrl.status,
                                     "skipped": "rota inexistente"})
            continue

        ctrl_session = _has_session_cookie(ctrl)
        test_session = _has_session_cookie(test)
        progress_json = "upload_progress_" in test.text
        ctrl_progress = "upload_progress_" in ctrl.text

        result["probes"].append({
            "url": url,
            "status": test.status,
            "ctrl_status": ctrl.status,
            "ctrl_sets_session": ctrl_session,
            "test_sets_session": test_session,
            "progress_json": progress_json,
        })

        if progress_json and not ctrl_progress:
            result["handler_active"] = True
            result["confidence"] = "alta"
            result["evidence"].append(
                f"POST multipart em {url} com {field_name} devolveu JSON "
                f"'upload_progress_*' (handler ativo)"
            )
            break

        if test_session and not ctrl_session:
            result["handler_active"] = True
            result["confidence"] = "media"
            result["evidence"].append(
                f"POST multipart em {url} com {field_name} abriu sessao "
                f"(PHPSESSID) e o POST de controle nao"
            )
            break

        if test_session and ctrl_session:
            result["evidence"].append(
                f"{url}: aplicacao abre sessao nos dois POSTs - oraculo inconclusivo"
            )

    if not result["evidence"]:
        result["evidence"].append(
            "handler session.upload_progress nao confirmado ativo "
            "(pode estar desligado, atras de CDN ou exigir session_start())"
        )
    return result


# --------------------------------------------------------------------------- #
# Ponte para o PoC externo EDB-52704
# --------------------------------------------------------------------------- #
EDB52704_LABEL = "EDB-52704 - php2shell one-click (OffSec, credito 9bie/eness)"
EDB52704_MAX_CMD = 14
EDB52704_DEFAULT_CMD = "id>p1"
EDB52704_DEFAULT_FETCH = "/p1"

_EXPLOIT_AUTO_TRIGGER = frozenset((
    "VULNERABLE", "LIKELY_VULNERABLE", "EOL_VULNERABLE",
    "PRIMITIVE_CONFIRMED", "CRASH_SIGNAL", "RCE_CONFIRMED",
))


def edb52704_available() -> bool:
    """Import tardio: o modulo nao pesa no boot do Cyberpm."""
    try:
        from php2shell_exploit import available
        return available()
    except Exception:
        return False


def run_edb52704(url: str, **kwargs: Any) -> Dict[str, Any]:
    from php2shell_exploit import run_edb52704 as _run
    return _run(url, **kwargs)


def _php_page(base: str, client: HttpClient) -> str:
    """Pagina PHP viva no diretorio do alvo; fallback: a propria URL."""
    fallback = base
    for url in _urls_for(base, PROBE_NAMES):
        r = client.get(url)
        if r.status == 200:
            return url
        if fallback == base and r.status in (301, 302, 401, 403, 500):
            fallback = url
    return fallback


# --------------------------------------------------------------------------- #
# Orquestracao
# --------------------------------------------------------------------------- #
def scan(url: str, timeout: float = DEFAULT_TIMEOUT, deep: bool = True,
         verify_tls: bool = False, field_name: str = UPLOAD_FIELD_DEFAULT,
         client: Optional[HttpClient] = None,
         active: bool = False, chain: str = "618", call_addr: int = 0,
         command: str = "id", expect: Optional[str] = None,
         stall: float = 1.5, variants: Optional[Sequence[str]] = None,
         max_paths: int = 4, progress_path: Optional[str] = None,
         stop: Optional[Any] = None, deadline: Optional[float] = None,
         exploit: str = "auto", exploit_cmd: str = "",
         exploit_fetch: Optional[str] = EDB52704_DEFAULT_FETCH,
         exploit_proof: Optional[str] = None, exploit_profile: str = "bookworm",
         exploit_zif: int = 0, exploit_dtor: int = 0, exploit_htdata: int = 0) -> Dict[str, Any]:
    """Executa a checagem completa e devolve um finding pronto para o relatorio."""
    t0 = time.time()
    base = _normalize(url)
    client = client or HttpClient(timeout=timeout, verify_tls=verify_tls)

    version, php_detected, fp_evidence = fingerprint(base, client)
    version_verdict = classify(version)

    oracle: Dict[str, Any] = {
        "handler_active": False, "confidence": "n/a", "field": field_name,
        "probes": [], "evidence": ["oraculo desativado (deep=False)"],
    }
    if deep:
        oracle = check_upload_progress(base, client, field_name=field_name)

    active_result: Optional[Dict[str, Any]] = None
    if active:
        from php2shell_active import active_scan
        active_result = active_scan(
            base, variants=variants, client=client, stop=stop, deadline=deadline,
            chain=chain, call_addr=call_addr, command=command,
            expect=expect.encode() if expect else None, stall=stall,
            timeout=timeout, verify_tls=verify_tls, max_paths=max_paths,
            progress_path=progress_path,
        )

    verdict = _combine(version_verdict, oracle["handler_active"])
    if active_result:
        verdict = _combine_active(verdict, active_result["status"])
    severity = _SEVERITY.get(verdict, "info")

    # ---- PoC externo EDB-52704 (auto: so com sinal; never: nunca) ----
    exploit_result: Optional[Dict[str, Any]] = None
    exploit_notes: List[str] = []
    should_run = (exploit == "always") or (exploit == "auto" and verdict in _EXPLOIT_AUTO_TRIGGER)
    if should_run:
        page = _php_page(base, client)
        exploit_result = run_edb52704(
            page,
            command=exploit_cmd or EDB52704_DEFAULT_CMD,
            fetch=exploit_fetch,
            proof_file=exploit_proof,
            profile=exploit_profile,
            zif_offset=exploit_zif,
            dtor_offset=exploit_dtor,
            htdata_offset=exploit_htdata,
            timeout=timeout,
        )
        if exploit_result.get("proof"):
            verdict = "RCE_CONFIRMED"
            severity = "critical"
            exploit_notes.append(
                f"PoC do EDB-52704 executou no alvo: PROOF {exploit_result['proof']!r} "
                f"(comando {exploit_result['command']!r})"
            )
        elif exploit_result.get("available"):
            exploit_notes.append(
                "PoC do EDB-52704 rodou sem PROOF: revise os offsets do build "
                "(--exploit-zif/--exploit-dtor) e o caminho do webroot."
            )
        else:
            exploit_notes.append(
                "PoC do EDB-52704 ausente: coloque em pocs/edb52704/exploit.py."
            )

    notes: List[str] = list(exploit_notes)
    if verdict == "RCE_CONFIRMED":
        notes.append(
            "O marcador do comando voltou no corpo da resposta: execucao de codigo "
            "no worker web. Confirme o usuario do processo e rotacione segredos."
        )
    elif verdict == "PRIMITIVE_CONFIRMED":
        notes.append(
            "A primitiva do CVE esta viva no alvo (fixacao de sessao ou monitor de "
            "upload_progress). Isso nao prova shell: o RCE depende dos offsets do build."
        )
    elif verdict == "CRASH_SIGNAL":
        notes.append(
            "O worker nao respondeu ao multipart em duas fases (502/503/504 ou 0 bytes). "
            "Confira segfaults no log do FPM desde 20/10/2026 e preserve os logs."
        )
    elif verdict == "VULNERABLE":
        notes.append(
            "Versao abaixo da correcao E handler upload_progress ativo: exposicao "
            "confirmada. A execucao de codigo depende dos offsets do build (cadeia 619)."
        )
    elif verdict == "LIKELY_VULNERABLE":
        notes.append(
            "Versao abaixo da correcao, mas o handler nao foi confirmado ativo. "
            "O banner pode vir de backport de distro - validar com php -v na maquina."
        )
    elif verdict == "EOL_VULNERABLE":
        notes.append(
            "Branch sem release oficial de correcao. Vale mitigar via php.ini ou recompilar."
        )
    elif verdict == "UNKNOWN":
        notes.append(
            "Versao nao exposta (CDN/proxy ocultando banner). Ausencia de versao "
            "nao significa seguro."
        )
    if active_result and active_result.get("chain_fallback"):
        notes.append("Cadeia 619 pedida sem --call/--dtor: as sondas 618 rodaram no lugar. "
                     "O RCE pela 619 depende do offset do build.")
    if not php_detected:
        notes.append("Nenhum indicio forte de PHP no alvo.")

    php_version_text = ".".join(map(str, version)) if version else None
    head = headline({"verdict": verdict, "php_version": php_version_text,
                     "active": active_result, "exploit": exploit_result})

    return {
        "module": MODULE_META["id"],
        "title": "PHP2Shell - RCE pre-autenticacao no nucleo do PHP",
        "cve": list(CVE_IDS),
        "cvss": CVSS,
        "target": base,
        "headline": head[0],
        "headline_reason": head[1],
        "headline_action": head[2],
        "exploit_used": exploit_used({"active": active_result, "exploit": exploit_result}),
        "verdict": verdict,
        "severity": severity,
        "php_version": php_version_text,
        "php_detected": php_detected,
        "upload_progress": oracle,
        "active": active_result,
        "active_status": (active_result or {}).get("status"),
        "exploit": exploit_result,
        "exploit_available": edb52704_available(),
        "notes": notes,
        "evidence": (fp_evidence + oracle["evidence"]
                     + (active_result or {}).get("evidence", [])
                     + (exploit_result or {}).get("evidence", [])),
        "remediation": REMEDIATION,
        "references": REFERENCES,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - t0, 2),
    }


def to_rows(finding: Dict[str, Any]) -> List[Tuple[str, str]]:
    active = finding.get("active") or {}
    ex = finding.get("exploit") or {}
    return [
        ("Alvo", finding.get("target", "")),
        ("Veredito direto", finding.get("headline", "")),
        ("CVE", ", ".join(finding.get("cve", []))),
        ("CVSS", finding.get("cvss", "")),
        ("Severidade", finding.get("severity", "")),
        ("Veredito", finding.get("verdict", "")),
        ("Versao PHP", finding.get("php_version") or "nao exposta"),
        ("upload_progress", "ativo" if finding.get("upload_progress", {}).get("handler_active")
         else "nao confirmado"),
        ("Teste ativo", _ACTIVE_LABEL.get(active.get("status"), "nao executado")),
        ("Fixacao de sessao", "sim" if active.get("session_fixation_hits") else "nao"),
        ("PoC EDB-52704", ("PROOF: " + ex["proof"]) if ex.get("proof")
         else "rodou sem proof" if ex.get("available") else
         "nao executado" if not ex else "ausente"),
        ("Evidencias", str(len(finding.get("evidence", [])))),
    ]


def write_evidence(out_dir: str, finding: Dict[str, Any]) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "php2shell.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(finding, fh, ensure_ascii=False, indent=2)
    return path


def run_murrez(repo_dir: str, target: str, mode: str = "check",
               extra_args: Sequence[str] = (), python: str = sys.executable,
               timeout: float = 300.0) -> Dict[str, Any]:
    poc = os.path.join(repo_dir, "poc.py")
    if not os.path.isfile(poc):
        return {"ok": False, "error": f"poc.py nao encontrado em {repo_dir!r}"}

    with tempfile.TemporaryDirectory() as tmp:
        targets = os.path.join(tmp, "targets.txt")
        out_jsonl = os.path.join(tmp, "results.jsonl")
        with open(targets, "w", encoding="utf-8") as fh:
            fh.write(target.rstrip("/") + "\n")

        cmd = [python, poc, mode, "-f", targets, "-o", out_jsonl, *extra_args]
        try:
            proc = subprocess.run(cmd, cwd=repo_dir, capture_output=True,
                                  text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"timeout apos {timeout}s", "cmd": cmd}

        results: List[Dict[str, Any]] = []
        if os.path.isfile(out_jsonl):
            with open(out_jsonl, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

        return {
            "ok": proc.returncode == 0,
            "cmd": cmd,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "results": results,
        }


# --------------------------------------------------------------------------- #
# Caca a versao do PHP (quando expose_php=Off)
# --------------------------------------------------------------------------- #
def _version_hunt(base: str, client: HttpClient,
                  budget: int = 26) -> Tuple[Optional[Tuple[int, int, int]], List[str]]:
    evidence: List[str] = []
    origin, directory = _origin(base), _base_dir(base)
    candidates: List[str] = []
    for name in HUNT_NAMES:
        candidates.append(origin + directory + name)
        if directory != "/":
            candidates.append(origin + "/" + name)
    for target in (base, origin + directory, origin + "/",
                   origin + directory + "cyberpm-nao-existe.php"):
        candidates.append(_join(target, _EG_QUERY))

    seen: List[str] = []
    for url in candidates:
        if url not in seen:
            seen.append(url)

    for url in seen[:budget]:
        r = client.get(url)
        if r.status != 200:
            continue
        found = parse_php_version(
            r.headers.get("x-powered-by", ""), r.headers.get("server", ""),
            r.text[:MAX_BODY],
        )
        if found:
            evidence.append(
                f"versao PHP {found[0]}.{found[1]}.{found[2]} obtida em {url}"
            )
            return found, evidence
    evidence.append(
        f"versao nao exposta: {len(seen[:budget])} caminhos testados sem banner PHP "
        "(expose_php=Off e sem phpinfo.php)"
    )
    return None, evidence


# --------------------------------------------------------------------------- #
# Veredito direto e exploit usado
# --------------------------------------------------------------------------- #
_EXPLOIT_NAMES = {
    "stall": "cadeia 618 - stall multipart em duas fases (~1,5s entre FILE_DATA) - dispara o use-after-free",
    "micro": "cadeia 618 - micro trigger (~290 bytes, POST unico)",
    "inject": "cadeia 618 - sonda de fixacao de sessao (PHPSESSID no corpo, sem Cookie)",
    "619": "cadeia 619 - spray de 149 registros forjados + zend_call_function -> zif_system",
}

_EXPLOIT_POCS = {
    "618": "PoC: github.com/murrez/php2shell (cadeia 618) e github.com/0x4148/CVE-2026-109618-php2shell-lab",
    "619": "PoC: github.com/Zer061/CVE-2026-109618 (forge 619)",
}


def exploit_used(finding: Dict[str, Any]) -> List[str]:
    active = finding.get("active") or {}
    ex = finding.get("exploit") or {}
    lines: List[str] = []
    if ex:
        lines.append("PoC externo: " + EDB52704_LABEL)
        if ex.get("proof"):
            lines.append(f"PROOF do PoC: {ex['proof']!r} (comando {ex.get('command')!r})")
        elif ex.get("available"):
            lines.append("PoC executado sem PROOF: revisar offsets do build "
                         "(--exploit-zif/--exploit-dtor)")
        else:
            lines.append("PoC ausente: pocs/edb52704/exploit.py")
        if ex.get("cmd"):
            lines.append("comando do PoC: " + ex["cmd"])
    if not active:
        lines.append("nenhuma sonda ativa - so fingerprint e oraculo passivo")
        return lines
    chain = active.get("chain") or "618"
    if chain == "619":
        lines.append(_EXPLOIT_NAMES["619"])
        lines.append(
            f"comando {active.get('command')!r} - call {active.get('call_addr')} - "
            f"cabe em 14 bytes: {active.get('command_inline_ok')}"
        )
    else:
        for variant in active.get("variants", []):
            lines.append(_EXPLOIT_NAMES.get(variant, variant))
    routes = active.get("probe_paths") or []
    if routes:
        lines.append("rotas sondadas: " + ", ".join(routes))
    lines.append(_EXPLOIT_POCS.get(chain, ""))
    if active.get("chain_fallback"):
        lines.append("cadeia 619 pedida sem offset: as sondas 618 rodaram no lugar")
    return [line for line in lines if line]


def headline(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    verdict = finding.get("verdict", "UNKNOWN")
    version = finding.get("php_version")

    if verdict == "RCE_CONFIRMED":
        if (finding.get("exploit") or {}).get("proof"):
            return ("VULNERAVEL - CODIGO EXECUTADO PELO POC",
                    "o PoC do EDB-52704 executou comando e trouxe a prova",
                    "atualizar agora e rotacionar segredos acessiveis ao worker web")
        return ("VULNERAVEL - CODIGO EXECUTADO NO SERVIDOR",
                "o marcador do comando voltou na resposta",
                "atualizar agora e rotacionar segredos acessiveis ao worker web")
    if verdict == "PRIMITIVE_CONFIRMED":
        return ("VULNERAVEL - PRIMITIVA DO CVE CONFIRMADA",
                "a falha respondeu ao teste ativo (fixacao de sessao ou monitor de upload_progress)",
                f"atualizar para {FIXED_TEXT} e reiniciar php-fpm/apache")
    if verdict == "CRASH_SIGNAL":
        return ("VULNERAVEL - WORKER MORREU NO TESTE",
                "o processo nao respondeu ao multipart em duas fases",
                f"atualizar para {FIXED_TEXT} e conferir segfaults no log do FPM")
    if verdict in ("VULNERABLE", "EOL_VULNERABLE"):
        return ("VULNERAVEL",
                f"versao {version} abaixo da correcao e a superficie de upload_progress respondeu",
                f"atualizar para {FIXED_TEXT}")
    if verdict == "LIKELY_VULNERABLE":
        return ("VULNERAVEL (PROVAVEL)",
                f"versao {version} esta abaixo da correcao; falta o sinal ativo",
                f"atualizar para {FIXED_TEXT} e confirmar o pacote com o administrador")
    if verdict == "PATCHED":
        return ("NAO VULNERAVEL PELA VERSAO",
                f"versao {version} ja esta na faixa corrigida",
                "confirmar o pacote instalado: backport de distro pode mentir no banner")
    return ("INCONCLUSIVO",
            "versao nao exposta e nenhum sinal do teste ativo",
            f"pedir a versao real ao administrador; a correcao e {FIXED_TEXT}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def open_window(parent, initial_target=""):
    from php2shell_window import open_window as open_scan_window
    return open_scan_window(parent, initial_target)


def _main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="php2shell",
        description="Detector de CVE-2026-109618 / CVE-2026-109619 (passivo + teste ativo + PoC).",
    )
    ap.add_argument("url", help="alvo, ex.: https://exemplo.com")
    ap.add_argument("--json", action="store_true", help="saida JSON completa")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--verify-tls", action="store_true",
                    help="validar certificado TLS (padrao: nao validar)")
    ap.add_argument("--no-deep", action="store_true", help="so fingerprint passivo")
    ap.add_argument("--active", action="store_true",
                    help="executa as sondas ativas (stall, micro, fixacao)")
    ap.add_argument("--chain", default="618", help="618 (padrao) ou 619 (exige --call)")
    ap.add_argument("--call", default="", help="endereco de zend_call_function (hex)")
    ap.add_argument("--dtor", default="", help="endereco de zval_ptr_dtor (call = dtor - delta)")
    ap.add_argument("--command", default="id", help="comando para a cadeia 619 (max 14 bytes)")
    ap.add_argument("--expect", default="", help="substring que confirma sucesso no corpo")
    ap.add_argument("--stall", type=float, default=1.5, help="pausa entre as fases (s)")
    ap.add_argument("--variants", default="", help="stall,micro,inject")
    ap.add_argument("--max-paths", type=int, default=4)
    ap.add_argument("--progress-url", default=None,
                    help="endpoint de monitor do lab (ex.: /check_progress.php)")
    ap.add_argument("--field", default=UPLOAD_FIELD_DEFAULT,
                    help="nome do campo (session.upload_progress.name)")
    ap.add_argument("--evidence-dir", help="pasta para gravar php2shell.json")
    ap.add_argument("--murrez-repo", help="pasta do PoC do murrez para confirmacao cruzada")
    ap.add_argument("--exploit", choices=("auto", "always", "never"), default="auto",
                    help="roda o PoC externo EDB-52704 (padrao: auto = so com sinal)")
    ap.add_argument("--exploit-cmd", default="",
                    help=f"comando do PoC (max {EDB52704_MAX_CMD} bytes)")
    ap.add_argument("--exploit-fetch", default=EDB52704_DEFAULT_FETCH,
                    help="caminho no webroot para buscar a prova via HTTP")
    ap.add_argument("--exploit-proof", default=None, help="arquivo local para a prova")
    ap.add_argument("--exploit-profile", choices=("bookworm", "lab"), default="bookworm",
                    help="build do alvo: imagem oficial php:8.4.26-apache ou lab")
    ap.add_argument("--exploit-zif", type=lambda x: int(x, 0), default=0,
                    help="offset de zif_system no libphp.so do alvo")
    ap.add_argument("--exploit-dtor", type=lambda x: int(x, 0), default=0,
                    help="offset de ZVAL_PTR_DTOR no libphp.so do alvo")
    ap.add_argument("--exploit-htdata", type=lambda x: int(x, 0), default=0,
                    help="offset chunk-relativo da string de 167 bytes")
    args = ap.parse_args(argv)

    call = 0
    if args.chain.lower().startswith("619") or args.call or args.dtor:
        from php2shell_active import resolve_call_addr
        call = resolve_call_addr(int(args.dtor, 0) if args.dtor else None,
                                 int(args.call, 0) if args.call else None)

    finding = scan(args.url, timeout=args.timeout, deep=not args.no_deep,
                   verify_tls=args.verify_tls, field_name=args.field,
                   active=args.active, chain=args.chain, call_addr=call,
                   command=args.command, expect=args.expect or None, stall=args.stall,
                   variants=tuple(v for v in args.variants.split(",") if v) or None,
                   max_paths=args.max_paths, progress_path=args.progress_url,
                   exploit=args.exploit, exploit_cmd=args.exploit_cmd,
                   exploit_fetch=args.exploit_fetch, exploit_proof=args.exploit_proof,
                   exploit_profile=args.exploit_profile, exploit_zif=args.exploit_zif,
                   exploit_dtor=args.exploit_dtor, exploit_htdata=args.exploit_htdata)

    if args.murrez_repo:
        finding["murrez"] = run_murrez(args.murrez_repo, finding["target"])
    if args.evidence_dir:
        finding["evidence_file"] = write_evidence(args.evidence_dir, finding)

    if args.json:
        print(json.dumps(finding, ensure_ascii=False, indent=2))
    else:
        print(f"VEREDITO: {finding['headline']}")
        print(f"Alvo: {finding['target']}")
        print(f"PHP: {finding.get('php_version') or 'nao exposta (expose_php=Off)'}")
        print(f"CVE: {', '.join(finding['cve'])} - CVSS {finding['cvss']}")
        print(f"Por que: {finding['headline_reason']}")
        print(f"Proximo passo: {finding['headline_action']}")
        ex = finding.get("exploit") or {}
        if ex:
            print("\\nPOC EXTERNO (EDB-52704):")
            print(f"  disponivel: {ex.get('available')}")
            print(f"  PROOF: {ex.get('proof') or '(sem proof)'}")
            if ex.get("error"):
                print(f"  aviso: {ex['error']}")
        print("\\nEXPLOIT USADO:")
        for line in finding["exploit_used"]:
            print(f"  - {line}")
        print("\\nDetalhes tecnicos:")
        for label, value in to_rows(finding):
            print(f"{label:<18}: {value}")
        for note in finding["notes"]:
            print(f"  - {note}")
        print("\\nEvidencias:")
        for item in finding["evidence"]:
            print(f"  * {item}")

    return 2 if finding["verdict"] in (
        "RCE_CONFIRMED", "PRIMITIVE_CONFIRMED", "CRASH_SIGNAL",
        "VULNERABLE", "LIKELY_VULNERABLE", "EOL_VULNERABLE") else 0


if __name__ == "__main__":
    raise SystemExit(_main())