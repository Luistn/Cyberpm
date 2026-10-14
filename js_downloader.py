#!/usr/bin/env python3
"""Bounded, cancellable public JavaScript downloader for authorized site reviews."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import md5
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


def download(item):
    url, folder, timeout = item
    name = md5(url.encode()).hexdigest()[:10] + '.js'
    dest = folder / name
    try:
        req = Request(url, headers={'User-Agent': 'PentestToolkit/9.2', 'Accept': 'application/javascript,text/javascript,*/*'})
        with urlopen(req, timeout=timeout) as response:
            typ = response.headers.get('Content-Type', '').lower()
            if 'text/html' in typ or 'application/json' in typ:
                return url, '', 'resposta não é JavaScript'
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                return url, '', 'arquivo maior que 2 MB'
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
    allowed = {host, 'siteassets.parastorage.com', 'static.parastorage.com'}
    urls = []
    for line in Path(a.list).read_text(errors='replace').splitlines():
        url = urljoin(base, line.strip())
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https') or parsed.hostname not in allowed:
            continue
        if url not in urls:
            urls.append(url)
    manifest = Path(a.manifest)
    errors = folder.parent / 'download_erros.tsv'
    with manifest.open('w') as good, errors.open('w') as bad:
        total = len(urls)
        print(f'[·] JS: {total} URLs válidas, até {min(max(a.workers,1),5)} downloads simultâneos', flush=True)
        with ThreadPoolExecutor(max_workers=min(max(a.workers,1),5)) as pool:
            jobs = [pool.submit(download, (url, folder, a.timeout)) for url in urls]
            for done, future in enumerate(as_completed(jobs), 1):
                url, name, error = future.result()
                if name:
                    good.write(f'{url}\t{name}\n'); good.flush()
                else:
                    bad.write(f'{url}\t{error}\n'); bad.flush()
                print(f'EVENT|JS_PROGRESS|{done}/{total}', flush=True)
                print(f'[·] JavaScript: {done}/{total} processados', flush=True)


if __name__ == '__main__':
    main()
