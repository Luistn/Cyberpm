#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell - Detector não destrutivo para CVE-2026-109618 / CVE-2026-109619
==========================================================================

Módulo autônomo para a fase de scan PHP do Cyberpm.

O QUE FAZ
  1. Fingerprint passivo da versão do PHP (X-Powered-By, Server, X-PHP-Version,
     cookie PHPSESSID, easter eggs do phpinfo com expose_php ligado).
  2. Compara a versão com a tabela oficial de correções e classifica o alvo.
  3. Oráculo ativo leve (~300 bytes): um POST multipart com o campo
     PHP_SESSION_UPLOAD_PROGRESS mais um POST de controle. Se o handler
     session.upload_progress estiver ativo, o PHP emite PHPSESSID e/ou o JSON
     "upload_progress_*" apenas no POST de teste -> exposição confirmada.

O QUE NÃO FAZ
  Não executa código, não faz heap shaping e não derruba workers. O RCE real
  depende dos offsets do build (cadeia 619). Para confirmar RCE, use
  run_murrez() contra o PoC do murrez.

REFERÊNCIAS
  https://vexday.io/pt/cve/CVE-2026-109618
  https://github.com/murrez/php2shell
  https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
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
    "scan",
    "fingerprint",
    "check_upload_progress",
    "parse_php_version",
    "classify",
    "to_rows",
    "write_evidence",
    "run_murrez",
    "HttpClient",
    "MODULE_META",
    "open_window",
]

VERSION = "1.0.0"
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
CVSS = "9.2 (CVSS v4.0)"

# Tabela oficial de correções. Qualquer versão anterior nesta branch é afetada.
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

# Metadados para o registro de fases do Cyberpm.
MODULE_META: Dict[str, Any] = {
    "id": "php2shell",
    "name": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
    "phase": "scan_php",
    "severity_max": "critical",
    "needs_network": True,
    "fast_mode": True,          # só 2 POSTs curtos: roda também no modo Rápido
    "destructive": False,
}

PROBE_PATHS: Tuple[str, ...] = ("/", "/index.php", "/wp-login.php", "/info.php", "/phpinfo.php")
ORACLE_PATHS: Tuple[str, ...] = ("/", "/index.php")
_EG_CREDITS = "/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

# Exige o prefixo "php" para não confundir versão de CMS com versão de PHP.
_RE_PHP_BANNER = re.compile(
    r"php[\s/_-]*(?:(?:version|fpm|cgi|cli|apache|module)[\s/:_-]*)?"
    r"(\d{1,2})\.(\d{1,2})\.(\d{1,3})",
    re.IGNORECASE,
)

_SEVERITY = {
    "VULNERABLE": "critical",
    "EOL_VULNERABLE": "critical",
    "LIKELY_VULNERABLE": "high",
    "PATCHED": "info",
    "UNKNOWN": "info",
}

REMEDIATION = [
    f"Atualizar o PHP para {FIXED_TEXT} (ou superior na mesma branch) e reiniciar o SAPI web.",
    "Branches EOL (5.x, 7.x, 8.0, 8.1) não têm release oficial: subir para 8.2+ ou "
    "recompilar com o patch de fonte do aviso do PHP.",
    "Mitigação temporária (aplicar as duas juntas, no php.ini efetivo do SAPI web e não "
    "sobrescrevível pela aplicação): session.upload_progress.enabled = 0 e memory_limit = -1. "
    "Depois reiniciar php-fpm / apache.",
    "Endurecer sessão: session.use_only_cookies = On.",
    "Docker: puxar imagens oficiais reconstruídas (as tags antigas continuam vulneráveis "
    "mesmo com o framework atualizado — a falha é no runtime, não no código da aplicação).",
    "Desconfiar de backport de distro: o banner pode mentir até você conferir php -v / "
    "changelog do pacote na máquina.",
]

REFERENCES = [
    "https://vexday.io/pt/cve/CVE-2026-109618",
    "https://github.com/murrez/php2shell",
    "https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC",
    "https://github.com/ikow/php2shell-poc",
    "https://sansec.io/research/php2shell",
]


# --------------------------------------------------------------------------- #
# HTTP mínimo
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
        except Exception as exc:  # timeout, TLS, DNS...
            return Response(url=url, status=0, elapsed=time.time() - t0,
                            error=f"{type(exc).__name__}: {exc}")

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, data: bytes, headers: Optional[Dict[str, str]] = None) -> Response:
        return self.request("POST", url, data=data, headers=headers)


# --------------------------------------------------------------------------- #
# Helpers puros (testáveis sem rede)
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


def parse_php_version(*texts: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Extrai (major, minor, patch) apenas de banners que citam PHP.

    Evita o clássico falso positivo "WordPress 6.8.11" lido como versão de PHP.
    """
    for text in texts:
        if not text:
            continue
        m = _RE_PHP_BANNER.search(text)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def classify(version: Optional[Tuple[int, int, int]]) -> str:
    """PATCHED | LIKELY_VULNERABLE | EOL_VULNERABLE | UNKNOWN"""
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
    """Combina veredito de versão com o oráculo. Função pura, coberta por teste."""
    if version_verdict == "PATCHED":
        return "PATCHED"
    if version_verdict == "EOL_VULNERABLE":
        return "VULNERABLE" if handler_active else "EOL_VULNERABLE"
    if version_verdict == "LIKELY_VULNERABLE":
        return "VULNERABLE" if handler_active else "LIKELY_VULNERABLE"
    return "LIKELY_VULNERABLE" if handler_active else "UNKNOWN"


def _build_multipart(fields: Dict[str, str],
                     files: Dict[str, Tuple[str, bytes, str]]) -> Tuple[bytes, str]:
    """Monta multipart/form-data. Campos vêm antes dos arquivos, como o rfc1867 exige."""
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
    """expose_php ligado: /?=PHPE9568F34-... devolve a página de créditos do PHP."""
    evidence: List[str] = []
    r = client.get(_join(base, _EG_CREDITS))
    if r.status == 200:
        version = parse_php_version(r.text)
        if version:
            evidence.append(
                f"easter egg phpinfo em {_EG_CREDITS} revelou PHP "
                f"{version[0]}.{version[1]}.{version[2]}"
            )
            return version, evidence
        if "php" in r.text.lower() and "credits" in r.text.lower():
            evidence.append(f"easter egg phpinfo confirmou PHP em {_EG_CREDITS} (sem versão)")
    return None, evidence


def fingerprint(base: str, client: HttpClient,
                paths: Sequence[str] = PROBE_PATHS,
                use_easter_egg: bool = True) -> Tuple[Optional[Tuple[int, int, int]], bool, List[str]]:
    """Retorna (versão, php_detectado, evidências). Não destrutivo."""
    evidence: List[str] = []
    version: Optional[Tuple[int, int, int]] = None
    php_detected = False

    for path in paths:
        url = _join(base, path)
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
                    f"versão PHP {found[0]}.{found[1]}.{found[2]} exposta no header "
                    f"{label}: {raw!r}"
                )
            if "php" in raw.lower():
                php_detected = True

        if _has_session_cookie(r):
            php_detected = True
            evidence.append(f"cookie de sessão PHP (PHPSESSID) emitido por {url}")

        low = r.text.lower()
        if "phpsessid" in low or "x-powered-by" in r.headers:
            php_detected = True

    if use_easter_egg and not version:
        egg_version, egg_evidence = _easter_egg(base, client)
        evidence.extend(egg_evidence)
        if egg_version:
            version = egg_version
            php_detected = True

    return version, php_detected, evidence


# --------------------------------------------------------------------------- #
# Camada 2 - oráculo session.upload_progress
# --------------------------------------------------------------------------- #
def check_upload_progress(base: str, client: HttpClient,
                          field_name: str = UPLOAD_FIELD_DEFAULT,
                          paths: Sequence[str] = ORACLE_PATHS) -> Dict[str, Any]:
    """POST de controle (sem o campo) x POST de teste (com o campo).

    Se só o POST de teste abrir sessão / devolver JSON de progresso, o handler
    session.upload_progress está ativo -> superfície exposta.
    """
    result: Dict[str, Any] = {
        "handler_active": False,
        "confidence": "baixa",
        "field": field_name,
        "probes": [],
        "evidence": [],
    }
    payload = "cyberpm"

    for path in paths:
        url = _join(base, path)

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
            result["confidence"] = "média"
            result["evidence"].append(
                f"POST multipart em {url} com {field_name} abriu sessão "
                f"(PHPSESSID) e o POST de controle não"
            )
            break

        if test_session and ctrl_session:
            result["evidence"].append(
                f"{url}: aplicação abre sessão nos dois POSTs - oráculo inconclusivo"
            )

    if not result["evidence"]:
        result["evidence"].append(
            "handler session.upload_progress não confirmado ativo "
            "(pode estar desligado, atrás de CDN ou exigir session_start())"
        )
    return result


# --------------------------------------------------------------------------- #
# Orquestração
# --------------------------------------------------------------------------- #
def scan(url: str, timeout: float = DEFAULT_TIMEOUT, deep: bool = True,
         verify_tls: bool = False, field_name: str = UPLOAD_FIELD_DEFAULT,
         client: Optional[HttpClient] = None) -> Dict[str, Any]:
    """Executa a checagem completa e devolve um finding pronto para o relatório."""
    t0 = time.time()
    base = _normalize(url)
    client = client or HttpClient(timeout=timeout, verify_tls=verify_tls)

    version, php_detected, fp_evidence = fingerprint(base, client)
    version_verdict = classify(version)

    oracle: Dict[str, Any] = {
        "handler_active": False, "confidence": "n/a", "field": field_name,
        "probes": [], "evidence": ["oráculo desativado (deep=False)"],
    }
    if deep:
        oracle = check_upload_progress(base, client, field_name=field_name)

    verdict = _combine(version_verdict, oracle["handler_active"])
    severity = _SEVERITY.get(verdict, "info")

    notes: List[str] = []
    if verdict == "VULNERABLE":
        notes.append(
            "Versão abaixo da correção E handler upload_progress ativo: exposição "
            "confirmada. A execução de código depende dos offsets do build (cadeia 619)."
        )
    elif verdict == "LIKELY_VULNERABLE":
        notes.append(
            "Versão abaixo da correção, mas o handler não foi confirmado ativo. "
            "O banner pode vir de backport de distro - validar com php -v na máquina."
        )
    elif verdict == "EOL_VULNERABLE":
        notes.append(
            "Branch sem release oficial de correção. Vale mitigar via php.ini ou recompilar."
        )
    elif verdict == "UNKNOWN":
        notes.append(
            "Versão não exposta (CDN/proxy ocultando banner). Ausência de versão "
            "não significa seguro."
        )
    if not php_detected:
        notes.append("Nenhum indício forte de PHP no alvo.")

    return {
        "module": MODULE_META["id"],
        "title": "PHP2Shell - RCE pré-autenticação no núcleo do PHP",
        "cve": list(CVE_IDS),
        "cvss": CVSS,
        "target": base,
        "verdict": verdict,
        "severity": severity,
        "php_version": ".".join(map(str, version)) if version else None,
        "php_detected": php_detected,
        "upload_progress": oracle,
        "notes": notes,
        "evidence": fp_evidence + oracle["evidence"],
        "remediation": REMEDIATION,
        "references": REFERENCES,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - t0, 2),
    }


def to_rows(finding: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Linhas (rótulo, valor) para a tabela do painel do Cyberpm."""
    return [
        ("CVE", ", ".join(finding.get("cve", []))),
        ("CVSS", finding.get("cvss", "")),
        ("Severidade", finding.get("severity", "")),
        ("Veredito", finding.get("verdict", "")),
        ("Versão PHP", finding.get("php_version") or "não exposta"),
        ("upload_progress", "ativo" if finding.get("upload_progress", {}).get("handler_active")
         else "não confirmado"),
        ("Evidências", str(len(finding.get("evidence", [])))),
    ]


def write_evidence(out_dir: str, finding: Dict[str, Any]) -> str:
    """Grava a evidência JSON na pasta da varredura (ex.: cyberpm-out/<site>/)."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "php2shell.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(finding, fh, ensure_ascii=False, indent=2)
    return path


def run_murrez(repo_dir: str, target: str, mode: str = "check",
               extra_args: Sequence[str] = (), python: str = sys.executable,
               timeout: float = 300.0) -> Dict[str, Any]:
    """Delegação opcional para o PoC do murrez (confirmação ativa de RCE)."""
    poc = os.path.join(repo_dir, "poc.py")
    if not os.path.isfile(poc):
        return {"ok": False, "error": f"poc.py não encontrado em {repo_dir!r}"}

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
            return {"ok": False, "error": f"timeout após {timeout}s", "cmd": cmd}

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
# CLI
# --------------------------------------------------------------------------- #
def open_window(parent, initial_target=""):
    """Open the desktop adapter without starting a scan on import or opening."""
    from php2shell_window import open_window as open_scan_window
    return open_scan_window(parent, initial_target)


def _main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="php2shell",
        description="Detector não destrutivo de CVE-2026-109618 / CVE-2026-109619.",
    )
    ap.add_argument("url", help="alvo, ex.: https://exemplo.com")
    ap.add_argument("--json", action="store_true", help="saída JSON completa")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--verify-tls", action="store_true",
                    help="validar certificado TLS (padrão: não validar)")
    ap.add_argument("--no-deep", action="store_true", help="só fingerprint passivo")
    ap.add_argument("--field", default=UPLOAD_FIELD_DEFAULT,
                    help="nome do campo (session.upload_progress.name)")
    ap.add_argument("--evidence-dir", help="pasta para gravar php2shell.json")
    ap.add_argument("--murrez-repo", help="pasta do PoC do murrez para confirmação ativa")
    args = ap.parse_args(argv)

    finding = scan(args.url, timeout=args.timeout, deep=not args.no_deep,
                   verify_tls=args.verify_tls, field_name=args.field)

    if args.murrez_repo:
        finding["murrez"] = run_murrez(args.murrez_repo, finding["target"])
    if args.evidence_dir:
        finding["evidence_file"] = write_evidence(args.evidence_dir, finding)

    if args.json:
        print(json.dumps(finding, ensure_ascii=False, indent=2))
    else:
        for label, value in to_rows(finding):
            print(f"{label:<18}: {value}")
        for note in finding["notes"]:
            print(f"  - {note}")
        print("\nEvidências:")
        for item in finding["evidence"]:
            print(f"  * {item}")

    return 0 if finding["verdict"] in ("PATCHED",) else 1


if __name__ == "__main__":
    raise SystemExit(_main())
