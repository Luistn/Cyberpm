"""Pure presentation and scope helpers."""
import re
import html
from urllib.parse import urljoin


def report_links(text, base_url=None):
    """Escape collected text and make HTTP(S) URLs clickable without loading them."""
    parts=[]
    end=0
    pattern=r'https?://[^\s<>"\x27]+'
    if base_url and base_url.startswith(('http://','https://')):
        pattern+=r'|(?m:^/[^\s<>"\x27]+)'
    for match in re.finditer(pattern, text):
        url=match.group().rstrip('.,;)')
        parts.append(html.escape(text[end:match.start()]))
        escaped=html.escape(url,quote=True)
        destination=html.escape(urljoin(base_url,url) if url.startswith('/') else url,quote=True)
        parts.append(f'<a href="{destination}" target="_blank" rel="noopener noreferrer">{escaped}</a>')
        parts.append(html.escape(match.group()[len(url):]))
        end=match.end()
    parts.append(html.escape(text[end:]))
    return ''.join(parts)


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
