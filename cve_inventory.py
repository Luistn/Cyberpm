"""Time-bounded inventory of CVE references from local tool evidence."""
import argparse
import json
from pathlib import Path
import re
import time

SOURCES = {
    'Nuclei': ('09_vulns/nuclei.txt', '09_vulns/nuclei.stdout', '09_vulns/nuclei.jsonl'),
    'Nmap': ('02_portas/nmap.xml', '02_portas/nmap.txt', '02_portas/nmap.stdout'),
    'Retire.js': ('29_js/retire.json',),
    'TLS': ('26_headers/testssl.json', '26_headers/testssl.stdout'),
}
EXECUTIONS = {'Nuclei': '09_vulns/nuclei.exec.txt', 'Nmap': '02_portas/nmap.exec.txt',
              'Retire.js': '29_js/retire.exec.txt', 'TLS': '26_headers/testssl.exec.txt'}
PATTERN = re.compile(rb'\bCVE-[0-9]{4}-[0-9]{4,}\b', re.I)


def collect(root, seconds=30, max_bytes=8_000_000):
    root = Path(root)
    started = time.monotonic()
    deadline = started + seconds
    evidence = set()
    sources = []
    for tool, paths in SOURCES.items():
        source = {'tool': tool, 'files': [], 'bytes_read': 0, 'diagnostics': []}
        for relative in paths:
            path = root / relative
            if not path.is_file():
                continue
            if time.monotonic() >= deadline:
                source['diagnostics'].append('limite de tempo atingido')
                break
            source['files'].append(relative)
            try:
                with path.open('rb') as stream:
                    read = 0
                    carry = b''
                    while read < max_bytes:
                        if time.monotonic() >= deadline:
                            source['diagnostics'].append('limite de tempo atingido')
                            break
                        block = stream.read(min(65536, max_bytes - read))
                        if not block:
                            break
                        read += len(block)
                        text = carry + block
                        # Carry the final bytes so an ID split across blocks is intact.
                        boundary = max(0, len(text) - 128)
                        for match in PATTERN.finditer(text):
                            if match.start() < boundary:
                                evidence.add((match[0].decode('ascii').upper(), relative))
                        carry = text[boundary:]
                    for match in PATTERN.finditer(carry):
                        evidence.add((match[0].decode('ascii').upper(), relative))
                    source['bytes_read'] += read
                    if read == max_bytes and stream.read(1):
                        source['diagnostics'].append('limite de leitura por arquivo atingido')
            except OSError:
                source['diagnostics'].append('falha ao ler evidência')
        if not source['files']:
            source['diagnostics'].append('evidência ausente ou não examinada')
        execution = root / EXECUTIONS[tool]
        if execution.is_file():
            try:
                with execution.open('r', encoding='utf-8', errors='replace') as stream:
                    fields = dict(line.strip().split('=', 1) for line in stream.read(8192).splitlines() if '=' in line)
                if fields.get('codigo') not in (None, '0') or fields.get('estado') == 'executando':
                    source['diagnostics'].append('ferramenta falhou, foi interrompida ou deixou saída parcial')
            except OSError:
                source['diagnostics'].append('estado de execução indisponível')
        if tool == 'Nmap':
            status = root / '02_portas/scan_status.json'
            if status.is_file():
                try:
                    with status.open(encoding='utf-8') as stream:
                        data = json.loads(stream.read(8192))
                    if not isinstance(data, dict) or not data.get('complete'):
                        source['diagnostics'].append('inventário Nmap incompleto/inconclusivo')
                except (OSError, ValueError):
                    source['diagnostics'].append('estado do inventário Nmap inválido')
        sources.append(source)
    ids = sorted({item[0] for item in evidence})
    partial = any(source['diagnostics'] for source in sources)
    return {'ids': ids, 'evidence': sorted(evidence), 'sources': sources, 'partial': partial,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'budget_seconds': seconds,
            'catalog_lookup': False}


def save(root, result):
    folder = Path(root) / '10_cves'
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'ids.txt').write_text(''.join(value + '\n' for value in result['ids']), encoding='utf-8')
    (folder / 'cves.txt').write_text(''.join(f'{source}: {cve}\n' for cve, source in result['evidence']), encoding='utf-8')
    lines = [f"CVEs: {len(result['ids'])} identificadores únicos nas evidências locais; limite {result['budget_seconds']}s."]
    if not result['ids']:
        lines.append('Nenhuma referência a CVE encontrada nas evidências examinadas; isso não comprova ausência de vulnerabilidades.')
    for source in result['sources']:
        detail = '; '.join(source['diagnostics']) or 'evidência examinada'
        lines.append(f"{source['tool']}: {len(source['files'])} arquivo(s), {source['bytes_read']} bytes; {detail}.")
    lines.append('Cobertura parcial/inconclusiva.' if result['partial'] else 'Leitura das evidências disponíveis concluída.')
    lines.append('Referências citadas não confirmam aplicabilidade ou exploração. Consulta externa a catálogo CVE não foi executada.')
    summary = '\n'.join(lines) + '\n'
    (folder / 'resumo.txt').write_text(summary, encoding='utf-8')
    (folder / 'status.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    result = collect(args.out)
    print(save(args.out, result), end='', flush=True)
    return 1 if result['partial'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
