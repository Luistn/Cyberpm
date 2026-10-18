#!/usr/bin/env python3
"""Bounded, cancellable public JavaScript downloader for authorized site reviews."""
import argparse
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import md5
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class SameHostRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        original, redirected = urlparse(req.full_url), urlparse(newurl)
        if (redirected.scheme not in ('http', 'https') or
                redirected.hostname != original.hostname or
                redirected.port != original.port or redirected.username or redirected.password):
            raise ValueError('redirecionamento fora do escopo')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(item):
    url, folder, timeout = item
    name = md5(url.encode()).hexdigest()[:10] + '.js'
    dest = folder / name
    try:
        req = Request(url, headers={'User-Agent': 'PentestToolkit/9.2', 'Accept': 'application/javascript,text/javascript,*/*'})
        with build_opener(SameHostRedirect()).open(req, timeout=timeout) as response:
            typ = response.headers.get('Content-Type', '').lower()
            if 'text/html' in typ or 'application/json' in typ:
                return url, '', 'resposta não é JavaScript'
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                return url, '', 'arquivo maior que 2 MB'
        prefix = data.lstrip()[:256].lower()
        if prefix.startswith((b'<!doctype html', b'<html', b'<head', b'<body')):
            return url, '', 'resposta HTML, não é JavaScript (possível página de erro/bloqueio)'
        if not data:
            return url, '', 'arquivo vazio'
        dest.write_bytes(data)
        return url, name, ''
    except Exception as exc:
        return url, '', str(exc)[:160]


def main():
    p = argparse.ArgumentParser()
    for arg in ('base', 'list', 'out', 'manifest'):
        p.add_argument('--' + arg, required=True)
    p.add_argument('--workers', type=int, default=5)
    p.add_argument('--timeout', type=float, default=8)
    a = p.parse_args()
    folder = Path(a.out); folder.mkdir(parents=True, exist_ok=True)
    base = a.base.rstrip('/') + '/'
    host = urlparse(base).hostname
    allowed = {host}
    urls = []
    for line in Path(a.list).read_text(errors='replace').splitlines():
        url = urljoin(base, line.strip())
        parsed = urlparse(url)
        if (parsed.scheme not in ('http', 'https') or parsed.hostname not in allowed
                or parsed.port != urlparse(base).port or parsed.username or parsed.password):
            continue
        if url not in urls:
            urls.append(url)
    manifest = Path(a.manifest)
    errors = folder.parent / 'download_erros.tsv'
    failures = 0
    with manifest.open('w', encoding='utf-8') as good, errors.open('w', encoding='utf-8') as bad:
        total = len(urls)
        print(f'[·] JS: {total} URLs candidatas no escopo, até {min(max(a.workers,1),5)} downloads simultâneos', flush=True)
        with ThreadPoolExecutor(max_workers=min(max(a.workers,1),5)) as pool:
            jobs = [pool.submit(download, (url, folder, a.timeout)) for url in urls]
            for done, future in enumerate(as_completed(jobs), 1):
                url, name, error = future.result()
                if name:
                    good.write(f'{url}\t{name}\n'); good.flush()
                else:
                    failures += 1
                    error = ' '.join(error.split())
                    bad.write(f'{url}\t{error}\n'); bad.flush()
                    print(f'[!] JS: falha em {url}: {error}', flush=True)
                    print('[!] REPRODUZIR: ' + shlex.join(['curl', '-sS', '--max-time', str(a.timeout), '-D', '-', '-o', '/dev/null', url]), flush=True)
                print(f'EVENT|JS_PROGRESS|{done}/{total}', flush=True)
                print(f'[·] JavaScript: {done}/{total} processados', flush=True)

    print(f'[·] JS: {total - failures} baixados · {failures} falhas · detalhes: {errors}', flush=True)
    if failures:
        print('[!] Coleta JS parcial/inconclusiva; HTTP 403 pode indicar recusa do servidor/WAF. Não comprova ausência de JavaScript.', flush=True)
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
