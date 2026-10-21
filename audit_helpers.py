"""Offline validation of scanner inputs and HTTP evidence (standard library only)."""
import argparse
import json
import ipaddress
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


def scoped_url(base, value):
    try:
        candidate = urlsplit(urljoin(base, value.strip()))
        origin = urlsplit(base)
        if (candidate.scheme not in ('http', 'https') or candidate.username
                or candidate.password or candidate.hostname != origin.hostname
                or candidate.port != origin.port):
            return None
        return urlunsplit(candidate._replace(fragment=''))
    except ValueError:
        return None


def normalize(base, lines):
    return sorted({url for line in lines if line.strip()
                   for url in [scoped_url(base, line)] if url})


def target_origin(base):
    target_host(base)
    parsed = urlsplit(base)
    return urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))


def target_host(base):
    parsed = urlsplit(base)
    host = parsed.hostname
    if parsed.scheme not in ('https', 'http') or not host or parsed.username or parsed.password:
        raise ValueError('alvo deve ser uma URL HTTP(S), sem credenciais')
    if parsed.port is not None and not 0 < parsed.port < 65536:
        raise ValueError('porta inválida')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
            raise ValueError('host inválido')
    return host


def api_kind(body):
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if isinstance(data.get('paths'), dict) and isinstance(data.get('info'), dict):
        if isinstance(data.get('openapi'), str) and data['openapi'].startswith('3.'):
            return 'OpenAPI'
        if data.get('swagger') == '2.0':
            return 'Swagger'
    # JSON by itself does not demonstrate an API or GraphQL endpoint.
    return None


def arjun_urls(base, data):
    urls = []
    if not isinstance(data, dict):
        return urls
    for url, result in data.items():
        scoped = scoped_url(base, url)
        if not scoped or not isinstance(result, dict) or result.get('method') != 'GET':
            continue
        params = result.get('params', [])
        if not isinstance(params, list):
            continue
        parts = urlsplit(scoped)
        original = parse_qsl(parts.query, keep_blank_values=True)
        existing = {key for key, _ in original}
        # One discovered parameter per URL avoids masking an individual result.
        for param in params:
            if isinstance(param, str) and param and param not in existing:
                urls.append(urlunsplit(parts._replace(query=urlencode(original + [(param, '1')]))))
    return sorted(set(urls))


def openapi_get_urls(base, data):
    # Only declared GET routes without required parameters can be checked generically.
    if not isinstance(data, dict) or not isinstance(data.get('paths'), dict):
        return []
    origin = urlsplit(base)
    root = urlunsplit((origin.scheme, origin.netloc, '/', '', ''))
    route_base = root
    if data.get('swagger') == '2.0':
        route_base = urljoin(root, str(data.get('basePath', '/')).lstrip('/')).rstrip('/') + '/'
    elif data.get('servers'):
        servers = data['servers']
        if not isinstance(servers, list) or not isinstance(servers[0], dict):
            return []
        server = servers[0].get('url', '')
        if not isinstance(server, str) or '{' in server:
            return []
        route_base = scoped_url(base, server)
        if not route_base:
            return []
        route_base = route_base.rstrip('/') + '/'
    candidates = []
    for path, item in data['paths'].items():
        if not isinstance(path, str) or not path.startswith('/') or '{' in path or not isinstance(item, dict):
            continue
        operation = item.get('get')
        if not isinstance(operation, dict):
            continue
        common, specific = item.get('parameters', []), operation.get('parameters', [])
        if not isinstance(common, list) or not isinstance(specific, list):
            continue
        parameters = common + specific
        if any(not isinstance(param, dict) or param.get('required') or '$ref' in param for param in parameters):
            continue
        candidates.append(urljoin(route_base, path.lstrip('/')))
    return normalize(base, candidates)


def sqli_sample(base, lines, limit=5):
    """Small deterministic sample; omit static assets and repeated parameter shapes."""
    selected=[]
    seen=set()
    static={'.js','.css','.map','.jpg','.jpeg','.png','.gif','.svg','.ico','.webp',
            '.woff','.woff2','.ttf','.eot','.pdf','.zip','.mp4','.mp3'}
    for url in normalize(base, lines):
        parts=urlsplit(url)
        if Path(parts.path.lower()).suffix in static:
            continue
        params=parse_qsl(parts.query,keep_blank_values=True)
        if not params or not any('=' in field for field in parts.query.split('&')):
            continue
        shape=(parts.netloc.lower(),parts.path,tuple(sorted({key for key,_ in params})))
        if shape in seen:
            continue
        seen.add(shape)
        selected.append(url)
        if len(selected)>=limit:
            break
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('urls', 'api', 'arjun', 'target', 'origin', 'schema-gets', 'sqli-sample'))
    parser.add_argument('--base', default='')
    parser.add_argument('file')
    args = parser.parse_args()
    if args.action in ('target', 'origin'):
        try:
            print(target_origin(args.file) if args.action == 'origin' else target_host(args.file))
        except ValueError as exc:
            print(str(exc), file=__import__('sys').stderr)
            return 1
        return 0
    path = Path(args.file)
    if args.action == 'api':
        kind = api_kind(path.read_bytes())
        if kind:
            print(kind)
        return 0 if kind else 1
    content = path.read_text(encoding='utf-8', errors='replace') if path.exists() else ''
    if args.action == 'sqli-sample':
        result = sqli_sample(args.base, content.splitlines())
    elif args.action == 'urls':
        result = normalize(args.base, content.splitlines())
    else:
        try:
            data = json.loads(content or '{}')
        except ValueError:
            print('Saída JSON incompleta ou inválida do Arjun', file=__import__('sys').stderr)
            return 1
        result = openapi_get_urls(args.base, data) if args.action == 'schema-gets' else arjun_urls(args.base, data)
    for url in result:
        print(url)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
