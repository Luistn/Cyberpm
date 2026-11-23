#!/usr/bin/env python3
"""Query ProjectDiscovery Vulnx for CVEs related to Nmap service versions."""
import argparse
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


def products(path):
    root = ET.parse(path).getroot()
    seen = set()
    for service in root.findall('.//port/service'):
        product = ' '.join((service.get('product') or '').split())
        version = ' '.join((service.get('version') or '').split())
        if not product:
            continue
        query = ' '.join(part for part in (product, version) if part).strip()
        if query and query.lower() not in seen:
            seen.add(query.lower())
            yield query


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nmap', required=True)
    parser.add_argument('--max-queries', type=int, default=5)
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    if not 1 <= args.max_queries <= 10:
        parser.error('--max-queries deve estar entre 1 e 10')
    if not 1 <= args.timeout <= 600:
        parser.error('--timeout deve estar entre 1 e 600 segundos')
    try:
        queries = list(products(args.nmap))[:args.max_queries]
    except (OSError, ET.ParseError) as exc:
        print(f'Vulnx: não foi possível ler o XML do Nmap: {exc}', file=sys.stderr)
        return 1
    if not queries:
        print('Vulnx: Nmap não identificou serviços com produto/versão para consultar.')
        return 0

    deadline = time.monotonic() + args.timeout
    errors = 0
    for index, query in enumerate(queries, 1):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            print('Vulnx: limite total atingido; consultas restantes não executadas.', file=sys.stderr)
            return 1
        print(f'[VULNX] Consulta {index}/{len(queries)}: {query}', flush=True)
        try:
            result = subprocess.run(
                ['vulnx', '--disable-update-check', 'search', query, '--limit', '10', '--json'],
                capture_output=True, text=True, timeout=min(15, remaining), check=False)
        except subprocess.TimeoutExpired:
            print(f'Vulnx: tempo limite na consulta {index}.', file=sys.stderr, flush=True)
            errors += 1
            continue
        except OSError as exc:
            print(f'Vulnx: falha ao executar a consulta {index}: {exc}', file=sys.stderr, flush=True)
            return 1
        if result.stdout:
            print(result.stdout.rstrip(), flush=True)
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr, flush=True)
        if result.returncode:
            print(f'Vulnx: consulta {index} terminou com código {result.returncode}.', file=sys.stderr, flush=True)
            errors += 1
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
