"""Offline inventory of literal HTTP calls, forms and OpenAPI operations."""
import argparse
import csv
import json
import re
from html.parser import HTMLParser
from pathlib import Path

from audit_helpers import scoped_url, target_origin

LITERAL = r'''(?P<quote>["'`])(?P<url>[^"'`\r\n]+)(?P=quote)'''
METHODS = {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}


def javascript(base, text):
    rows = set()

    def add(value, method):
        if '${' in value or '{' in value or '\\' in value:
            return
        url = scoped_url(base, value)
        if url:
            rows.add((url, method if method in METHODS else 'UNKNOWN'))

    for match in re.finditer(r'\bfetch\s*\(\s*' + LITERAL, text):
        # Restrict options to this call; do not borrow another call's method.
        suffix = text[match.end():]
        options = re.match(r'\s*,\s*\{([^{}]*)', suffix)
        method = re.search(r'''\bmethod\s*:\s*["']([A-Za-z]+)["']''', options[1]) if options else None
        add(match['url'], method[1].upper() if method else ('UNKNOWN' if re.match(r'\s*,', suffix) else 'GET'))
    for match in re.finditer(r'(?<![\w$])(?:axios|\$)\.(get|head|options|post|put|patch|delete)\s*\(\s*' + LITERAL, text, re.I):
        add(match['url'], match[1].upper())
    for match in re.finditer(r'''\.open\s*\(\s*["'](GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)["']\s*,\s*''' + LITERAL, text, re.I):
        add(match['url'], match[1].upper())
    for match in re.finditer(r'(?:\baxios|\$\.ajax)\s*\(\s*\{([^{}]*)', text):
        url = re.search(r'\burl\s*:\s*' + LITERAL, match[1])
        method = re.search(r'''\b(?:method|type)\s*:\s*["']([A-Za-z]+)["']''', match[1])
        if url:
            add(url['url'], method[1].upper() if method else 'UNKNOWN')
    for match in re.finditer(LITERAL, text):
        value = match['url']
        # Preserve literal root-relative endpoints even without a recognized API call.
        if value.startswith(('/', 'https://', 'http://')):
            url = scoped_url(base, value)
            if url and not any(row[0] == url for row in rows):
                add(value, 'UNKNOWN')
    return sorted(rows)


class Forms(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.rows = set()
        self.scripts = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            url = scoped_url(self.base, attrs.get('action') or self.base)
            method = (attrs.get('method') or 'GET').upper()
            if url and method in ('GET', 'POST'):
                self.rows.add((url, method))
        elif tag == 'script':
            self.in_script = not attrs.get('src')

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts.append(data)


def schema_operations(base, data):
    if not isinstance(data, dict) or not isinstance(data.get('paths'), dict):
        return []
    route_base = target_origin(base) + '/'
    if data.get('swagger') == '2.0':
        value = data.get('basePath', '/')
        route_base = scoped_url(route_base, value) if isinstance(value, str) else None
    elif data.get('servers'):
        servers = data['servers']
        if not isinstance(servers, list) or not isinstance(servers[0], dict):
            return []
        value = servers[0].get('url', '/')
        route_base = scoped_url(route_base, value) if isinstance(value, str) and '{' not in value else None
    if not route_base:
        return []
    rows = set()
    for path, operations in data['paths'].items():
        if not isinstance(path, str) or not path.startswith('/') or not isinstance(operations, dict):
            continue
        url = scoped_url(route_base.rstrip('/') + '/', path.lstrip('/'))
        if not url:
            continue
        for method, operation in operations.items():
            if method.upper() in METHODS and isinstance(operation, dict):
                rows.add((url, method.upper()))
    return sorted(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--js', action='store_true')
    args = parser.parse_args()
    out = Path(args.out)
    rows = set()
    manifest = out / '29_js/manifest.tsv'
    if manifest.exists():
        for line in manifest.read_text(encoding='utf-8', errors='replace').splitlines():
            parts = line.split('\t')
            if len(parts) < 2:
                continue
            source, name = parts[:2]
            if Path(name).name != name:
                continue
            path = out / '29_js/arquivos' / name
            if path.is_file():
                # Browser HTTP calls resolve relative to the document, not the JS file.
                for url, method in javascript(args.base, path.read_text(encoding='utf-8', errors='replace')):
                    rows.add((url, source, method))
    if not args.js:
        for path in (out / '08_codigo/index.html', out / '03_tech/home.html'):
            if path.exists():
                text = path.read_text(encoding='utf-8', errors='replace')
                forms = Forms(args.base)
                forms.feed(text)
                for url, method in forms.rows | set(javascript(args.base, '\n'.join(forms.scripts))):
                    rows.add((url, args.base, method))
        for path in sorted((out / '06_api').glob('*.body')):
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
            except (ValueError, OSError):
                continue
            for url, method in schema_operations(args.base, data):
                rows.add((url, str(path.name), method))
    destination = out / ('29_js/endpoints.tsv' if args.js else '06_api/operacoes.tsv')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t')
        writer.writerow(('Endpoint', 'Arquivo', 'Metodo'))
        writer.writerows(sorted(rows))
    if not args.js:
        # Do not silently invoke a declared POST/DELETE route with GET.
        candidates = sorted({url for url, _, method in rows if method in ('GET', 'UNKNOWN') and '{' not in url})
        (out / '06_api/endpoints_get.txt').write_text(''.join(url + '\n' for url in candidates), encoding='utf-8')


if __name__ == '__main__':
    main()
