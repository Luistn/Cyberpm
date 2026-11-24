"""Small CTF operations and argument builders used by the desktop panel."""
import base64
from collections import defaultdict
import hashlib
import ipaddress
from pathlib import Path
import re
import os
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def generate_wordlist(seeds, suffixes='', variations=True, limit=50000):
    """Combine classroom vocabulary with suffixes, deduplicated in stable order."""
    if len(seeds) + len(suffixes) > 1_000_000:
        raise ValueError('Use até 1 MB de palavras e sufixos.')
    words = list(dict.fromkeys(line.strip() for line in seeds.splitlines() if line.strip()))
    endings = list(dict.fromkeys([''] + [line.strip() for line in suffixes.splitlines() if line.strip()]))
    if not words:
        raise ValueError('Digite pelo menos uma palavra-base, uma por linha.')
    result = {}
    for word in words:
        forms = [word, word.lower(), word.upper(), word.capitalize()] if variations else [word]
        for form in dict.fromkeys(forms):
            for ending in endings:
                candidate = form + ending
                if len(candidate) > 256:
                    raise ValueError('Cada candidata pode ter até 256 caracteres.')
                result[candidate] = None
                if len(result) > limit:
                    raise ValueError(f'A lista excede {limit:,} candidatas. Reduza as palavras ou sufixos.')
    return list(result)


def save_wordlist(path, words):
    destination = Path(path).expanduser().resolve()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write('\n'.join(words) + '\n')
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def local_file(value):
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError('Selecione um arquivo existente.')
    return str(path)


def recover_xor(text, known_prefix='CTF{'):
    data = bytes.fromhex(text)
    prefix = known_prefix.encode('utf-8')
    if not data or not prefix:
        raise ValueError('Informe os bytes e um prefixo conhecido, como CTF{.')
    key = data[0] ^ prefix[0]
    result = bytes(value ^ key for value in data)
    if not result.startswith(prefix):
        raise ValueError('O prefixo não corresponde a uma chave XOR de um byte para essa mensagem.')
    try:
        decoded = result.decode('utf-8')
    except UnicodeDecodeError:
        decoded = result.hex(' ')
    return f'Chave hexadecimal: {key:02x}\nTexto: {decoded}'


def transform(text, operation, key='2a', known_prefix='CTF{'):
    if operation == 'Descobrir chave XOR':
        return recover_xor(text, known_prefix)
    if operation == 'Base64 → texto':
        data = base64.b64decode(''.join(text.split()), validate=True)
    elif operation == 'Texto → Base64':
        return base64.b64encode(text.encode('utf-8')).decode('ascii')
    elif operation == 'Hexadecimal → texto':
        data = bytes.fromhex(text)
    elif operation == 'Texto → hexadecimal':
        return text.encode('utf-8').hex(' ')
    elif operation == 'XOR de um byte':
        number = int(key.removeprefix('0x'), 16)
        if not 0 <= number <= 255:
            raise ValueError('A chave hexadecimal precisa estar entre 00 e ff.')
        data = bytes(value ^ number for value in bytes.fromhex(text))
    else:
        raise ValueError('Escolha uma operação.')
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return 'Saída binária em hexadecimal\n' + data.hex(' ')


def file_report(value):
    path = Path(local_file(value))
    digest = hashlib.sha256()
    sample = bytearray()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            digest.update(block)
            if len(sample) < 2_000_000:
                sample.extend(block[:2_000_000-len(sample)])
    data = bytes(sample)
    signatures = [(b'\x89PNG\r\n\x1a\n', 'PNG'), (b'\xff\xd8\xff', 'JPEG'),
                  (b'%PDF-', 'PDF'), (b'PK\x03\x04', 'ZIP ou formato baseado em ZIP'),
                  (b'GIF87a', 'GIF'), (b'GIF89a', 'GIF'), (b'\x7fELF', 'ELF')]
    kind = next((name for signature, name in signatures if data.startswith(signature)),
                'Não identificado pelas assinaturas deste painel')
    strings = re.findall(rb'[\x20-\x7e]{4,}', data)
    return (f'Arquivo: {path}\nTamanho: {path.stat().st_size} bytes\nAssinatura: {kind}\n'
            f'SHA-256: {digest.hexdigest()}\nPrimeiros 32 bytes: {data[:32].hex(" ")}\n\n'
            'Texto imprimível nos primeiros 2 MB (até 500 trechos)\n' +
            '\n'.join(part.decode('ascii') for part in strings[:500]))


def dynamic_xor_report(source):
    """Recover candidates for the crazyx0r sample without executing its source."""
    source = Path(local_file(source))
    code = source.read_text(encoding='utf-8', errors='replace')
    if 'dynamic_xor_encrypt' not in code or 'gen_priv_key' not in code:
        raise ValueError('O arquivo selecionado não parece ser o main.py do desafio crazyx0r.')
    companion = source.with_name('flag.txt')
    if not companion.is_file():
        raise ValueError('Não encontrei flag.txt ao lado de main.py. Importe o ZIP completo.')
    note = companion.read_text(encoding='utf-8', errors='replace')
    a_match = re.search(r'\ba\s*=\s*(\d+)', note)
    encoded = re.search(r"['\"]([A-Za-z0-9+/]{8,}={0,2})['\"]", note)
    if not a_match or not encoded:
        raise ValueError('flag.txt precisa conter o valor de a e o texto Base64 entre aspas.')
    a = int(a_match.group(1))
    cipher = base64.b64decode(encoded.group(1), validate=True)
    candidates = []
    for b in range(9, 22, 3):
        c = (a | b) ** 2
        key = str(c).encode('ascii')
        reversed_plain = bytes(value ^ key[index % len(key)] for index, value in enumerate(cipher))
        plain = reversed_plain[::-1]
        if all(32 <= value < 127 for value in plain):
            candidates.append((b, c, plain.decode('ascii')))
    if not candidates:
        return f'a informado: {a}\nNenhuma combinação gerou texto ASCII imprimível. Confira que os dois arquivos vieram do mesmo ZIP.'
    primary = next(((b,c,plain) for b,c,plain in candidates
                    if re.fullmatch(r'[A-Z][A-Z0-9_-]{2,}\[[A-Za-z0-9_-]{6,}\]', plain)), None)
    if primary:
        b,c,plain = primary
        alternatives = [item for item in candidates if item != primary]
        lines = [f'a informado: {a}', f'RESPOSTA RECUPERADA: {plain}',
                 f'Parâmetros usados: a={a}, b={b}, c={c}']
        if alternatives:
            lines.append('Outros resultados imprimíveis (menos compatíveis com o formato de flag):')
            lines.extend(f'b={other_b} · c={other_c} · {other_plain}'
                         for other_b,other_c,other_plain in alternatives)
        return '\n'.join(lines)
    lines = [f'a informado: {a}', 'Candidatos imprimíveis; confira o formato indicado pelo desafio:']
    lines.extend(f'b={b} · c={c} · candidato: {plain}' for b, c, plain in candidates)
    return '\n'.join(lines)


def http_file_report(value):
    path = Path(local_file(value))
    with path.open('rb') as source:
        data = source.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError('Use uma resposta HTTP salva com até 2 MB.')
    parts = re.split(rb'\r?\n\r?\n', data, maxsplit=1)
    lines = parts[0].decode('iso-8859-1').splitlines()
    if not lines or not re.match(r'^HTTP/\d(?:\.\d)?\s+\d{3}\b', lines[0]):
        raise ValueError('O arquivo deve começar com uma linha de resposta, como HTTP/1.1 200 OK.')
    body = parts[1].decode('utf-8', errors='replace') if len(parts) == 2 else ''
    return ('STATUS\n'+lines[0]+'\n\nCABEÇALHOS\n'+'\n'.join(lines[1:])+
            '\n\nCORPO DA RESPOSTA\n'+body+
            '\n\nDica: cabeçalhos ficam antes da primeira linha em branco. '
            'No desafio Cabeçalho suspeito, examine X-Lab-Trace.')


def log_report(value, query=''):
    path = Path(local_file(value))
    groups = defaultdict(lambda: {'FAIL': 0, 'OK': 0, 'events': []})
    matches = []
    lines = 0
    with path.open(encoding='utf-8', errors='replace') as source:
        for line in source:
            lines += 1
            if lines > 100_000:
                break
            if query and query not in line:
                continue
            if len(matches) < 500:
                matches.append(line.rstrip())
            ip = re.search(r'\bip=([0-9a-fA-F:.]+)', line)
            status = re.search(r'\b(FAIL|OK)\b', line)
            user = re.search(r'\buser=([^\s]+)', line)
            if ip and status:
                record = groups[(ip[1], user[1] if user else '(não informado)')]
                record[status[1]] += 1
                if len(record['events']) < 100:
                    record['events'].append(status[1])
    summary = ['Eventos ip= / user=, na ordem do arquivo (até 100 por grupo)']
    for (ip, user), record in sorted(groups.items()):
        summary.append(f'{ip} · usuário {user} · FAIL={record["FAIL"]} OK={record["OK"]}\n'
                       + ' → '.join(record['events']))
    return ('\n'.join(summary) + '\n\nLinhas correspondentes (até 500; leitura de até 100.000 linhas)\n'
            + '\n'.join(matches))


def target_url(value):
    parsed = urlsplit(value.strip())
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Informe uma URL http:// ou https:// completa.')
    if parsed.username or parsed.password:
        raise ValueError('Use o campo Cookie para sessão; remova credenciais da URL.')
    _ = parsed.port
    return value.strip()


def replace_query(url, name, value):
    parsed = urlsplit(target_url(url))
    name = name.strip()
    if not name or any(char in name for char in '\r\n\0'):
        raise ValueError('Informe o nome do parâmetro, como q.')
    query = [(key, item) for key, item in parse_qsl(parsed.query, keep_blank_values=True) if key != name]
    query.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def host_name(value):
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if not value or len(value) > 253 or not all(
                re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                for part in value.rstrip('.').split('.')):
            raise ValueError('Use somente um IP ou nome de host, sem caminho ou protocolo.')
        return value


def port_range(value):
    value = value.strip()
    for item in value.split(','):
        bounds = item.split('-')
        if len(bounds) > 2 or not all(part.isdigit() and 1 <= int(part) <= 65535 for part in bounds):
            raise ValueError('Portas inválidas. Exemplo: 80,443,8780-8789.')
        if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
            raise ValueError('O início do intervalo deve ser menor que o fim.')
    return value


def nmap_command(host, ports):
    host = host_name(host)
    return ['nmap'] + (['-6'] if ':' in host else []) + [
        '-sT', '-Pn', '-p', port_range(ports), host]


def capture_command(path, mode, display_filter='', stream='0', validate_file=True):
    source = local_file(path) if validate_file else str(path)
    args = ['tshark', '-n', '-r', source]
    if mode == 'Conversa TCP':
        number = int(stream)
        if number < 0:
            raise ValueError('O índice TCP deve ser zero ou maior.')
        return args + ['-q', '-z', f'follow,tcp,ascii,{number}']
    if mode == 'Consultas DNS':
        return args + ['-Y', 'dns.flags.response == 0', '-T', 'fields', '-e', 'dns.qry.name']
    if display_filter.strip():
        args += ['-Y', display_filter.strip()]
    return args + ['-c', '1000']


def web_command(mode, url, cookie=''):
    url = target_url(url)
    if any(char in cookie for char in '\r\n\0'):
        raise ValueError('Cookie inválido. Use uma única linha.')
    if mode == 'Resposta e cabeçalhos':
        args = ['curl', '--max-time', '30', '--max-filesize', '2097152', '-i']
        if cookie:
            args += ['--cookie', cookie]
        return args + ['--', url]
    if mode == 'SQLmap':
        args = ['sqlmap', '-u', url, '--batch', '--level=1', '--risk=1',
                '--threads=1', '--timeout=8', '--retries=1']
        if cookie:
            args += ['--cookie', cookie]
        return args
    if mode == 'Dalfox (XSS)':
        args = ['dalfox', 'url', url, '--worker', '1', '--timeout', '8']
        if cookie:
            args += ['--cookie', cookie]
        return args
    raise ValueError('Escolha uma operação web.')
