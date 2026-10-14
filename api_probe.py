"""Bounded GET/OPTIONS API checks; reports metadata without response values."""
import argparse
import base64
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from audit_helpers import normalize


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def auth_headers(environ):
    mode = environ.get('AUTH_MODE', 'none')
    secret = environ.get('AUTH_SECRET', '')
    headers = {'User-Agent': 'CyberOps-API-review', 'Accept': 'application/json'}
    if mode == 'bearer':
        headers['Authorization'] = 'Bearer ' + secret
    elif mode == 'cookie':
        headers['Cookie'] = secret
    elif mode == 'basic':
        value = environ.get('AUTH_USER', '') + ':' + environ.get('AUTH_PASS', '')
        headers['Authorization'] = 'Basic ' + base64.b64encode(value.encode()).decode()
    return headers


def summarize(body):
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return 'não JSON'
    if isinstance(data, dict):
        return 'JSON objeto: ' + str(len(data)) + ' campos (valores omitidos)'
    if isinstance(data, list):
        return 'JSON lista: ' + str(len(data)) + ' itens (valores omitidos)'
    return 'JSON ' + type(data).__name__


def probe(opener, url, method, headers, timeout):
    start = time.monotonic()
    result = {'url': url, 'method': method, 'status': None}
    try:
        try:
            response = opener.open(Request(url, headers=headers, method=method), timeout=timeout)
        except HTTPError as exc:
            response = exc
        with response:
            result['status'] = response.code
            result['content_type'] = response.headers.get('Content-Type', '')
            result['allow'] = response.headers.get('Allow', '')
            result['acao'] = response.headers.get('Access-Control-Allow-Origin', '')
            result['acac'] = response.headers.get('Access-Control-Allow-Credentials', '')
            body = response.read(65537)
            result['bytes_sampled'] = min(len(body), 65536)
            result['truncated'] = len(body) > 65536
            result['structure'] = 'amostra truncada' if result['truncated'] else summarize(body)
            status = response.code
            if status in (401, 403):
                result['assessment'] = 'acesso recusado; não comprova autorização correta'
            elif 300 <= status < 400:
                result['assessment'] = 'redirecionamento não seguido'
            elif status == 429:
                result['assessment'] = 'limite de requisições; interromper coleta'
            elif status >= 500:
                result['assessment'] = 'erro do servidor; revisar'
            elif status == 405:
                result['assessment'] = 'método não permitido'
            elif 200 <= status < 300:
                result['assessment'] = 'resposta recebida; não comprova vulnerabilidade'
            else:
                result['assessment'] = 'revisar status HTTP'
    except (URLError, TimeoutError, OSError, ValueError):
        # Exception text can contain URLs or credentials; keep the report generic.
        result['assessment'] = 'falha de conexão, TLS ou tempo limite'
    result['elapsed_ms'] = round((time.monotonic() - start) * 1000)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', required=True)
    parser.add_argument('--candidates', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--limit', type=int, default=8)
    args = parser.parse_args()
    # Preserve priority: schema routes first, followed by other candidates.
    urls = list(dict.fromkeys(url for line in Path(args.candidates).read_text().splitlines()
                            for url in normalize(args.base, [line])))
    # Do not copy query values or credentials into documents.
    urls = [url for url in urls if not urlsplit(url).query][:max(0, min(args.limit, 12))]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    opener = build_opener(NoRedirect())
    headers = auth_headers(os.environ)
    # Save after each call to retain evidence if the enclosing timeout interrupts.
    for url in urls:
        for method in ('GET', 'OPTIONS'):
            request_headers = dict(headers)
            if method == 'OPTIONS':
                request_headers['Origin'] = 'https://audit.invalid'
                request_headers['Access-Control-Request-Method'] = 'GET'
            row = probe(opener, url, method, request_headers, 4)
            rows.append(row)
            (out / 'api_resultados.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
            with (out / 'api_resultados.tsv').open('w', encoding='utf-8') as stream:
                stream.write('URL\tMétodo\tHTTP\tTempo_ms\tTipo\tEstrutura\tAvaliação\tAllow\tACAO\tACAC\n')
                for item in rows:
                    values = [item.get(key, '') for key in ('url', 'method', 'status', 'elapsed_ms', 'content_type', 'structure', 'assessment', 'allow', 'acao', 'acac')]
                    stream.write('\t'.join(str(value).replace('\t', ' ').replace('\n', ' ').replace('\r', '') for value in values) + '\n')
            print(f"[·] API {method}: HTTP {row['status']} · {row['elapsed_ms']} ms · {url}", flush=True)
            if row['status'] == 429:
                return 0
            time.sleep(0.5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
