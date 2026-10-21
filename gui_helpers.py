"""Pure presentation and scope helpers."""
import re
import html
import csv
from urllib.parse import urljoin, quote
from pathlib import Path


def execution_outcome(code, finished=False, stopped=False):
    """A completed scan can retain a nonzero code for partial coverage."""
    if stopped:
        return 'Interrompido', 'Execução interrompida', True
    if code == 0:
        return 'Executado', 'Execução concluída', False
    if code == 1 and finished:
        return 'Executado com ressalvas', 'Execução concluída com ressalvas', True
    return f'Erro ({code})', 'Execução encerrada com erro', True


def secret_rows(output_dir):
    """Read current-run TSVs with CSV quoting, keeping complete values and location."""
    root = Path(output_dir)
    rows, seen = [], set()
    for relative in ('29_js/segredos.tsv', '18_ident/dados_sensiveis_mascarados.tsv'):
        path = root / relative
        if not path.is_file():
            continue
        with path.open(encoding='utf-8-sig', errors='replace', newline='') as stream:
            for entry in csv.DictReader(stream, delimiter='\t'):
                if not entry.get('Tipo') or not entry.get('Valor'):
                    continue
                filename = entry.get('Arquivo') or ''
                line = entry.get('Linha') or ''
                column = entry.get('Coluna') or ''
                if not line:
                    prefix, separator, suffix = filename.rpartition(':')
                    if separator and suffix.isdigit():
                        filename, line = prefix, suffix
                row = {'type': entry['Tipo'], 'value': entry['Valor'], 'source': filename,
                       'line': line, 'column': column,
                       'url': entry.get('URL de origem') or entry.get('URL') or ''}
                key = tuple(row[field] for field in ('type', 'value', 'source', 'line', 'column'))
                if key not in seen:
                    rows.append(row)
                    seen.add(key)
    return rows


def report_path_link(path, root, label=None):
    """Portable link to an existing evidence file or directory in this run."""
    label=str(path) if label is None else label
    root=Path(root).resolve()
    candidate=Path(path)
    if not candidate.is_absolute():
        candidate=root/candidate
    try:
        relative=candidate.resolve().relative_to(root)
        if not candidate.exists():
            return report_links(label)
    except (ValueError,OSError):
        return report_links(label)
    href='./'+quote(relative.as_posix(),safe='/')
    if candidate.is_dir():
        href+='/'
    return f'<a href="{html.escape(href,quote=True)}" target="_blank" rel="noopener noreferrer">{html.escape(label)}</a>'


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
