"""Local exposure inventory with redacted values; no credential validation or use."""
import argparse
from bisect import bisect_right
import csv
import hashlib
import hmac
import json
import re
import secrets
from pathlib import Path


PATTERNS = {
    'CPF (checksum válido; revisar contexto)': re.compile(r'(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)'),
    'E-mail': re.compile(r'[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}'),
    'Chave candidata': re.compile(r'AIza[\w-]{35}|AKIA[A-Z0-9]{16}|(?:sk_live_|ghp_|github_pat_|xox[baprs]-)[\w-]{16,}'),
    'JWT candidato': re.compile(r'eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}'),
    'Chave privada candidata': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'Senha/segredo atribuído (candidato)': re.compile(r'''(?i)["']?(?:password|passwd|senha|api[_-]?key|client[_-]?secret|access[_-]?token)["']?\s*[:=]\s*["']([^"'\r\n]{4,})["']'''),
}


def valid_cpf(value):
    digits = re.sub(r'\D', '', value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for length in (9, 10):
        total = sum(int(digits[index]) * (length+1-index) for index in range(length))
        check = (total*10) % 11
        if (0 if check == 10 else check) != int(digits[length]):
            return False
    return True


def inspect_text(text, source, salt):
    rows = []
    newlines = [match.start() for match in re.finditer('\n', text)]
    for kind, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group()
            if kind.startswith('CPF') and not valid_cpf(value):
                continue
            digest = hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:16]
            rows.append({'type': kind, 'source': source, 'line': bisect_right(newlines, match.start())+1,
                         'column': match.start()-text.rfind('\n', 0, match.start()),
                         'value': '[VALOR OCULTO]', 'reference': digest, 'assessment': 'candidato; validar contexto e permissões'})
            if len(rows) >= 200:
                return rows
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--js-only', action='store_true')
    args = parser.parse_args()
    root = Path(args.out).resolve()
    files = [] if args.js_only else [root/'08_codigo'/'index.html', root/'04_crawl'/'urls.txt']
    directories = ('29_js/arquivos',) if args.js_only else ('29_js/arquivos', '05_exposicao/conteudo')
    for directory in directories:
        folder = root/directory
        if folder.is_dir():
            files.extend(sorted(folder.iterdir())[:60])
    rows = []
    salt = secrets.token_bytes(32)
    for path in files:
        # Do not follow file symlinks outside the collected evidence.
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
            continue
        with path.open('rb') as stream:
            content = stream.read(2_000_000).decode('utf-8', errors='replace')
        rows.extend(inspect_text(content, str(path.relative_to(root)), salt))
        if len(rows) >= 2000:
            rows=rows[:2000]
            break
    if args.js_only:
        manifest=root/'29_js'/'manifest.tsv'
        urls={}
        if manifest.is_file():
            for line in manifest.read_text(errors='replace').splitlines():
                parts=line.split('\t')
                if len(parts)==2:
                    from urllib.parse import urlsplit, urlunsplit
                    parsed=urlsplit(parts[0])
                    urls['29_js/arquivos/'+parts[1]]=urlunsplit(parsed._replace(query='',fragment=''))
        with (root/'29_js'/'segredos.tsv').open('w', encoding='utf-8', newline='') as stream:
            writer=csv.writer(stream,delimiter='\t')
            writer.writerow(['Tipo','Valor','Arquivo','Linha','Coluna','URL de origem'])
            for row in rows:
                writer.writerow([row['type'],row['value'],row['source'],row['line'],row['column'],urls.get(row['source'],'')])
        return 0
    folder = root/'18_ident'; folder.mkdir(exist_ok=True)
    (folder/'dados_sensiveis_mascarados.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    with (folder/'dados_sensiveis_mascarados.tsv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t')
        writer.writerow(['Tipo', 'Arquivo', 'Linha', 'Coluna', 'Valor', 'Referência', 'Avaliação'])
        for row in rows:
            writer.writerow([row[key] for key in ('type', 'source', 'line', 'column', 'value', 'reference', 'assessment')])
    print(f'[·] Exposições candidatas: {len(rows)} · valores mascarados · arquivo: {folder / "dados_sensiveis_mascarados.tsv"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
