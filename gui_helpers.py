"""Pure presentation and scope helpers."""
import re


def log_tag(line):
    text = line.lower()
    if '[achado crítico]' in text or '[achado alto]' in text:
        return 'critical'
    if any(mark in text for mark in ('[erro]', '[x]', 'traceback', 'error:', 'fatal')):
        return 'error'
    if any(mark in text for mark in ('[aviso]', '[!]', 'falha', 'ausente', 'não instalado')):
        return 'warning'
    if '══' in line or re.search(r'\bFASE\s+\d+', line):
        return 'phase'
    if '[achado' in text:
        return 'finding'
    if '[✓]' in line or '[relatório]' in text:
        return 'success'
    if '[·]' in line or '[tg]' in text:
        return 'info'
    return 'normal'


def scoped_subdomains(lines, parent):
    parent = parent.lower().rstrip('.')
    found = set()
    for line in lines:
        host = line.strip().lower().rstrip('.')
        if host.startswith('*.'):
            host = host[2:]
        if len(host) > 253 or not host.endswith('.' + parent):
            continue
        if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            found.add(host)
    return sorted(found)
