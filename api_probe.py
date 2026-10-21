"""GET/OPTIONS review and explicit HTTP test plans; reports response metadata."""
import argparse
import base64
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urljoin, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from audit_helpers import normalize, target_origin


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def auth_headers(environ):
    mode = environ.get('AUTH_MODE', 'none')
    secret = environ.get('AUTH_SECRET', '')
    headers = {'User-Agent': 'Cyberpm-API-review', 'Accept': 'application/json'}
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


def response_signals(body):
    """Describe field categories without storing returned personal values."""
    import re
    signals = []
    text = body.decode('utf-8', errors='replace') if isinstance(body, bytes) else body
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    categories = set()
    stack = [data]
    examined = 0
    while stack and examined < 1000:
        item = stack.pop(); examined += 1
        if isinstance(item, dict):
            for key, value in item.items():
                name = re.sub(r'[^a-z]', '', str(key).lower())
                if name in ('cpf', 'cnpj', 'email', 'phone', 'telefone', 'address', 'endereco', 'birthdate', 'datanascimento'):
                    categories.add('identificadores/contato')
                if name in ('password', 'senha', 'accesstoken', 'refreshtoken', 'secret', 'apikey'):
                    categories.add('credenciais/tokens')
                if isinstance(value, (dict, list)): stack.append(value)
        elif isinstance(item, list):
            stack.extend(item[:50])
    if categories:
        signals.append('Campos a revisar: ' + ', '.join(sorted(categories)) + '; presença não comprova vazamento')
    if any(marker in text.lower() for marker in ('traceback (most recent call last)', 'sqlstate[', 'stack trace:', 'fatal error:')):
        signals.append('Possível detalhe de erro interno; validar manualmente')
    return signals


def invalid_cpf_urls(base, schema):
    """Only declared GET query parameters; never guess IDs or invoke recovery POSTs."""
    if not isinstance(schema, dict): return []
    servers = schema.get('servers', [{'url': '/'}])
    if not servers or not isinstance(servers[0], dict): return []
    server = urljoin(base.rstrip('/') + '/', servers[0].get('url', '/'))
    paths = schema.get('paths', {})
    if not isinstance(paths, dict): return []
    result = []
    for path, methods in paths.items():
        if not isinstance(methods, dict) or not path.startswith('/') or '{' in path: continue
        operation = methods.get('get')
        if not isinstance(operation, dict): continue
        params = methods.get('parameters', []) + operation.get('parameters', [])
        if not all(isinstance(param, dict) for param in params): continue
        cpf = next((p for p in params if p.get('in') == 'query' and p.get('name', '').lower() == 'cpf'), None)
        if not cpf or any(p.get('required') and p is not cpf for p in params): continue
        route = server.rstrip('/') + path
        scoped = normalize(base, [route])
        if not scoped: continue
        result += [scoped[0] + '?' + urlencode({cpf['name']: value}) for value in ('22222222', '22222222222')]
        if len(result) >= 4: break
    return result


def probe(opener, url, method, headers, timeout, data=None):
    start = time.monotonic()
    result = {'url': url, 'method': method, 'status': None}
    try:
        try:
            response = opener.open(Request(url, data=data, headers=headers, method=method), timeout=timeout)
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
            result['signals'] = response_signals(body)
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


def request_plan(base, path):
    """Validate every explicit request before allowing any writes to be sent."""
    entries = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(entries, list) or len(entries) > 40:
        raise ValueError('O plano deve ser uma lista com até 40 requisições.')
    result = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Requisição inválida no plano.')
        method = str(entry.get('method', '')).upper()
        if method not in ('GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'):
            raise ValueError('Use GET, HEAD, OPTIONS, POST, PUT, PATCH ou DELETE; UPDATE corresponde a PUT/PATCH.')
        value = entry.get('url')
        urls = normalize(base, [value]) if isinstance(value, str) else []
        if not urls or target_origin(urls[0]) != target_origin(base) or '{' in urls[0]:
            raise ValueError('O plano deve usar URLs concretas na mesma origem do alvo.')
        expected = entry.get('expected_status', [])
        if not isinstance(expected, list) or any(type(code) is not int or not 100 <= code <= 599 for code in expected):
            raise ValueError('expected_status deve conter códigos HTTP inteiros.')
        headers = entry.get('headers', {})
        if (not isinstance(headers, dict) or any(not isinstance(key, str) or not isinstance(val, str)
                or any(char in key + val for char in '\r\n') for key, val in headers.items())):
            raise ValueError('Cabeçalhos inválidos no plano.')
        if any(key.lower() in ('host', 'content-length', 'transfer-encoding') for key in headers):
            raise ValueError('Host e enquadramento HTTP são definidos pelo transporte.')
        headers = dict(headers)
        if 'json' in entry and 'body' in entry:
            raise ValueError('Informe json ou body, não ambos.')
        data = None
        if 'json' in entry:
            data = json.dumps(entry['json']).encode('utf-8')
            if not any(key.lower() == 'content-type' for key in headers):
                headers['Content-Type'] = 'application/json'
        elif 'body' in entry:
            if not isinstance(entry['body'], str):
                raise ValueError('body deve ser texto.')
            data = entry['body'].encode('utf-8')
        if data is not None and len(data) > 65536:
            raise ValueError('Corpo de teste limitado a 64 KiB.')
        result.append({'url': urls[0], 'method': method, 'headers': headers,
                       'data': data, 'expected_status': expected})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', required=True)
    parser.add_argument('--candidates', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--limit', type=int, default=8)
    parser.add_argument('--schemas-dir')
    parser.add_argument('--request-plan', help='JSON com rotas, métodos e dados explícitos de teste')
    parser.add_argument('--execute-plan', action='store_true', help='Executa as requisições do plano, inclusive alterações')
    args = parser.parse_args()
    if args.execute_plan and not args.request_plan:
        parser.error('--execute-plan requer --request-plan')
    try:
        plan = request_plan(args.base, args.request_plan) if args.request_plan else []
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
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
    def save():
        (out / 'api_resultados.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
        keys = ('url', 'method', 'status', 'session', 'elapsed_ms', 'content_type', 'structure', 'assessment', 'allow', 'acao', 'acac', 'signals', 'comparison', 'workflow', 'test', 'validation')
        with (out / 'api_resultados.tsv').open('w', encoding='utf-8') as stream:
            stream.write('\t'.join(keys) + '\n')
            for item in rows:
                stream.write('\t'.join(str(item.get(key, '')).replace('\t', ' ').replace('\n', ' ').replace('\r', '') for key in keys) + '\n')
    for item in plan:
        if not args.execute_plan:
            row = {'url': item['url'], 'method': item['method'], 'status': None,
                   'assessment': 'planejada; não executada (requer --execute-plan)'}
        else:
            request_headers = dict(headers)
            request_headers.update(item['headers'])
            row = probe(opener, item['url'], item['method'], request_headers, 8, data=item['data'])
            expected = item['expected_status']
            row['validation'] = ('status esperado' if row['status'] in expected else 'status diferente do esperado') if expected else 'sem critério de status configurado'
            row['session'] = 'configurada' if any(key.lower() in ('authorization', 'cookie') for key in request_headers) else 'anônima'
        row['test'] = 'plano explícito de requisições'
        rows.append(row)
        save()
        print(f"[·] API plano {row['method']}: HTTP {row['status']} · {row['assessment']}", flush=True)
        if row['status'] == 429 or (args.execute_plan and row['status'] is None):
            return 1
        if args.execute_plan and item['expected_status'] and row['status'] not in item['expected_status']:
            print('[!] API plano: status inesperado; operações seguintes não executadas.', flush=True)
            return 1
        if args.execute_plan:
            time.sleep(0.5)
    # Save after each call to retain evidence if the enclosing timeout interrupts.
    for url in urls:
        for method in ('GET', 'OPTIONS'):
            request_headers = dict(headers)
            if method == 'OPTIONS':
                request_headers['Origin'] = 'https://audit.invalid'
                request_headers['Access-Control-Request-Method'] = 'GET'
            row = probe(opener, url, method, request_headers, 4)
            row['session'] = 'configurada' if 'Authorization' in headers or 'Cookie' in headers else 'anônima'
            if any(term in urlsplit(url).path.lower() for term in ('forgot', 'reset', 'recover', 'recuper', 'senha')):
                row['workflow'] = 'Recuperação de conta: validar mensagens, tempo e tokens com contas de teste; nenhum envio automático.'
            rows.append(row)
            if method == 'GET' and ('Authorization' in headers or 'Cookie' in headers):
                anonymous = probe(opener, url, 'GET', auth_headers({}), 4)
                anonymous['session'] = 'anônima'
                anonymous['comparison'] = ('Resposta anônima acessível; revisar se o recurso deve ser público'
                                           if anonymous['status'] and 200 <= anonymous['status'] < 300
                                           else 'Acesso anônimo recusado ou inconclusivo; validar autorização por objeto separadamente')
                rows.append(anonymous)
            save()
            print(f"[·] API {method}: HTTP {row['status']} · {row['elapsed_ms']} ms · {url}", flush=True)
            for signal in row.get('signals', []):
                print('[!] API: ' + signal, flush=True)
            if row['status'] == 429 or any(item.get('status') == 429 for item in rows):
                return 0
            time.sleep(0.5)
    if args.schemas_dir:
        candidates = []
        for path in sorted(Path(args.schemas_dir).glob('*.body'))[:20]:
            if path.stat().st_size > 2000000: continue
            try:
                schema = json.loads(path.read_text(encoding='utf-8'))
                candidates.extend(invalid_cpf_urls(args.base, schema))
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        for url in list(dict.fromkeys(candidates))[:4]:
            row = probe(opener, url, 'GET', headers, 4)
            row['test'] = 'CPF fictício inválido; comprimento/checksum'
            row['expected'] = 'Rejeição de entrada inválida, sem retornar dados pessoais'
            row['validation'] = ('entrada rejeitada' if row['status'] in (400, 422) else
                                 'acesso recusado' if row['status'] in (401, 403) else
                                 'revisar resposta; HTTP isolado não comprova falha')
            rows.append(row); save()
            print(f"[·] API CPF inválido: HTTP {row['status']} · {row['validation']}", flush=True)
            for signal in row.get('signals', []):
                print('[!] API CPF inválido: ' + signal, flush=True)
            if row['status'] == 429 or any(item.get('status') == 429 for item in rows): break
            time.sleep(0.5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
