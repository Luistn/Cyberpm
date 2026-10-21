#!/usr/bin/env python3
"""Cyberpm Precision Pack - esquema unico de achados, dedupe, severidade e exportacao.

Somente biblioteca padrao. Nao faz rede. Consumido por verify.py e relatorios.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

VERSION = '1.0.0'

# classe -> (nome legivel, CWE, OWASP 2021, CVSS base, severidade base)
CLASS_META = {
    'sqli':          ('SQL Injection',              'CWE-89',  'A03:2021', 8.2, 'alto'),
    'xss':           ('Cross-Site Scripting',       'CWE-79',  'A03:2021', 6.1, 'medio'),
    'open_redirect': ('Open Redirect',              'CWE-601', 'A01:2021', 4.3, 'baixo'),
    'cors':          ('CORS mal configurado',       'CWE-942', 'A05:2021', 5.4, 'medio'),
    'lfi':           ('Path Traversal / LFI',       'CWE-22',  'A01:2021', 7.5, 'alto'),
    'ssti':          ('Server-Side Template Inj.',  'CWE-1336','A03:2021', 8.8, 'alto'),
    'crlf':          ('CRLF Injection',             'CWE-93',  'A03:2021', 5.3, 'medio'),
    'ssrf':          ('SSRF',                       'CWE-918', 'A10:2021', 7.2, 'alto'),
    'host_header':   ('Host Header Injection',      'CWE-20',  'A05:2021', 5.3, 'medio'),
    'methods':       ('Metodos HTTP habilitados',   'CWE-650', 'A05:2021', 3.7, 'baixo'),
    'headers':       ('Cabecalhos de seguranca',    'CWE-693', 'A05:2021', 3.1, 'baixo'),
    'exposure':      ('Exposicao de recurso',       'CWE-538', 'A05:2021', 5.3, 'medio'),
    'default_cred':  ('Credencial padrao',          'CWE-1392','A07:2021', 8.8, 'alto'),
}

SEV_LADDER = ['info', 'baixo', 'medio', 'alto', 'critico']
VERDICT_RANK = {'confirmado': 4, 'provavel': 3, 'possivel': 2, 'refletido': 2,
                'nao_reproduzido': 1, 'inconclusivo': 0}

_ALIASES = {
    'sql': 'sqli', 'sql_injection': 'sqli', 'sqlinjection': 'sqli', 'injection_sql': 'sqli',
    'cross_site_scripting': 'xss', 'reflected_xss': 'xss', 'dom_xss': 'xss',
    'redirect': 'open_redirect', 'openredirect': 'open_redirect', 'unvalidated_redirect': 'open_redirect',
    'cors_misconfig': 'cors', 'cors_misconfiguration': 'cors',
    'path_traversal': 'lfi', 'traversal': 'lfi', 'local_file_inclusion': 'lfi',
    'template_injection': 'ssti', 'server_side_template_injection': 'ssti',
    'crlf_injection': 'crlf', 'header_injection': 'crlf', 'response_splitting': 'crlf',
    'server_side_request_forgery': 'ssrf',
    'host_header_injection': 'host_header', 'hostheader': 'host_header',
    'http_methods': 'methods', 'security_headers': 'headers',
}


def _norm_class(value):
    key = re.sub(r'[^a-z0-9]+', '_', str(value or '').lower()).strip('_')
    return _ALIASES.get(key, key if key in CLASS_META else None)


def veredito(nome, confianca, evidencia=None, reproducao='', nota=''):
    """Retorno padrao de um verificador."""
    return {'veredito': nome, 'confianca': int(max(0, min(100, confianca))),
            'evidencia': evidencia or {}, 'reproducao': reproducao, 'nota': nota}


def severity_for(classe, verdict):
    base = CLASS_META.get(classe, (None,) * 5)[4] or 'info'
    idx = SEV_LADDER.index(base) if base in SEV_LADDER else 0
    if verdict == 'confirmado':
        pass
    elif verdict == 'provavel':
        idx = max(0, idx - 1)
    elif verdict in ('possivel', 'refletido'):
        idx = max(0, idx - 2)
    else:
        idx = 0
    return SEV_LADDER[idx]


def _canon_url(url):
    try:
        parts = urlsplit(str(url).strip())
    except ValueError:
        return str(url).strip()
    return parts._replace(fragment='').geturl()


def dedupe_key(classe, url, param):
    parts = urlsplit(url)
    return '|'.join((classe, parts.netloc.lower(), parts.path, param or ''))


def make_id(*parts):
    return hashlib.sha1('|'.join(str(p) for p in parts).encode()).hexdigest()[:12]


def make_finding(classe, url, param='', payload='', verdict='inconclusivo', confianca=0,
                 evidencia=None, reproducao='', origem='', nota='', extra=None):
    classe = _norm_class(classe) or str(classe).lower()
    url = _canon_url(url)
    meta = CLASS_META.get(classe, (classe, 'CWE-000', 'A00:2021', 0.0, 'info'))
    item = {
        'id': make_id(classe, url, param, payload),
        'classe': classe, 'nome': meta[0], 'cwe': meta[1], 'owasp': meta[2],
        'cvss_base': meta[3], 'severidade': severity_for(classe, verdict),
        'url': url, 'param': param, 'payload': payload,
        'veredito': verdict, 'confianca': int(confianca),
        'evidencia': evidencia or {}, 'reproducao': reproducao,
        'origem': origem, 'nota': nota,
    }
    if extra:
        item.update(extra)
    return item


def dedupe(items):
    """Mantem o melhor achado por (classe, host, path, param)."""
    best = {}
    for item in items:
        key = dedupe_key(item['classe'], item['url'], item.get('param', ''))
        cur = best.get(key)
        if cur is None or (VERDICT_RANK.get(item['veredito'], 0), item['confianca']) > \
                           (VERDICT_RANK.get(cur['veredito'], 0), cur['confianca']):
            best[key] = item
    order = {'critico': 0, 'alto': 1, 'medio': 2, 'baixo': 3, 'info': 4}
    return sorted(best.values(), key=lambda i: (order.get(i['severidade'], 9),
                                                -i['confianca'], i['classe'], i['url']))


def summarize(items):
    resumo = {'total': len(items), 'por_severidade': {}, 'por_veredito': {}, 'confirmados': 0}
    for item in items:
        resumo['por_severidade'][item['severidade']] = resumo['por_severidade'].get(item['severidade'], 0) + 1
        resumo['por_veredito'][item['veredito']] = resumo['por_veredito'].get(item['veredito'], 0) + 1
        if item['veredito'] == 'confirmado':
            resumo['confirmados'] += 1
    return resumo


def to_json(items, path):
    Path(path).write_text(json.dumps({'cyberpm': VERSION, 'resumo': summarize(items),
                                      'achados': items}, ensure_ascii=False, indent=2),
                          encoding='utf-8')


def to_csv(items, path):
    cols = ['id', 'severidade', 'classe', 'nome', 'cwe', 'owasp', 'cvss_base', 'veredito',
            'confianca', 'url', 'param', 'payload', 'reproducao', 'origem', 'nota']
    with Path(path).open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t')
        writer.writerow(cols)
        for item in items:
            writer.writerow([str(item.get(c, '')).replace('\t', ' ').replace('\n', ' ') for c in cols])


def to_markdown(items, target=''):
    out = [f'# Relatorio Cyberpm Precision Pack', f'Alvo: {target}', '']
    resumo = summarize(items)
    out.append('| Severidade | Qtd |')
    out.append('|---|---|')
    for sev in SEV_LADDER:
        if resumo['por_severidade'].get(sev):
            out.append(f'| {sev} | {resumo["por_severidade"][sev]} |')
    out.append('')
    for item in items:
        out += [f'## [{item["severidade"].upper()}] {item["nome"]} — {item["veredito"]} ({item["confianca"]}%)',
                f'- **URL:** {item["url"]}',
                f'- **Parametro:** {item["param"] or "-"}',
                f'- **Payload:** `{item["payload"]}`' if item['payload'] else '- **Payload:** -',
                f'- **CWE / OWASP:** {item["cwe"]} / {item["owasp"]}',
                f'- **Nota:** {item["nota"]}' if item['nota'] else '',
                f'- **Reproduzir:** `{item["reproducao"]}`' if item['reproducao'] else '',
                f'- **Evidencia:** `{json.dumps(item["evidencia"], ensure_ascii=False)[:500]}`', '']
    return '\n'.join(l for l in out if l is not None)


def to_sarif(items, target=''):
    rules = {}
    for classe, meta in CLASS_META.items():
        rules[classe] = {
            'id': classe, 'name': meta[0],
            'shortDescription': {'text': meta[0]},
            'helpUri': f'https://owasp.org/Top10/{meta[2].replace(":", "")}/',
            'properties': {'cwe': meta[1], 'owasp': meta[2], 'cvss': meta[3]},
        }
    level = {'critico': 'error', 'alto': 'error', 'medio': 'warning', 'baixo': 'note', 'info': 'note'}
    results = []
    for item in items:
        results.append({
            'ruleId': item['classe'],
            'level': level.get(item['severidade'], 'note'),
            'message': {'text': f'{item["nome"]} ({item["veredito"]}, {item["confianca"]}%) em {item["url"]}'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': item['url']}}}],
            'properties': {'param': item['param'], 'payload': item['payload'],
                           'confianca': item['confianca'], 'veredito': item['veredito']},
        })
    return json.dumps({
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
        'runs': [{'tool': {'driver': {'name': 'Cyberpm Precision Pack', 'version': VERSION,
                                      'rules': list(rules.values())}},
                  'originalUriBaseIds': {'ROOT': {'uri': target or '/'}},
                  'results': results}],
    }, ensure_ascii=False, indent=2)


def export(items, base_path, target=''):
    base = Path(base_path)
    to_json(items, base.with_suffix('.json'))
    to_csv(items, base.with_suffix('.tsv'))
    base.with_suffix('.md').write_text(to_markdown(items, target), encoding='utf-8')
    base.with_suffix('.sarif').write_text(to_sarif(items, target), encoding='utf-8')
    return [str(base.with_suffix(s)) for s in ('.json', '.tsv', '.md', '.sarif')]