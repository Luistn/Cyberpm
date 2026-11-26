"""Small CTF operations and argument builders used by the desktop panel."""
import base64
import binascii
from collections import defaultdict
import hashlib
from heapq import nsmallest
import ipaddress
from pathlib import Path
import re
import os
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


TEST_FLAG_BODIES = r'(?:fake_flag_for_testing|f4k3_fl4g_for_t3st1ng)'
TEST_FLAG_PATTERN = re.compile(r'\b(?:CTF|CASCO|HTB)\{' + TEST_FLAG_BODIES + r'\}', re.IGNORECASE)
FLAG_PATTERN = re.compile(r'\b(?:(?:CTF|CASCO|HTB|(?i:flag))\{(?!(?i:' + TEST_FLAG_BODIES + r')\})[^{}\s]{1,150}\}|CASCO\[[^\[\]\s]{1,150}\])')
ELF_TEXT_WORDS = re.compile(rb'(?:[\x21-\x7e]\x00\x00\x00){5,}')
CAPTURE_SUFFIXES = {'.pcap', '.pcapng', '.cap'}
ENCODING_OPERATIONS = {'.b64': 'Base64 → texto', '.base64': 'Base64 → texto',
                       '.hex': 'Hexadecimal → texto'}


def local_evidence_guide(path):
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in CAPTURE_SUFFIXES:
        return ('Capturas', ['tshark', '-n', '-r', str(path), '-c', '1000'],
                'Clique em Ler com TShark para ver os pacotes na saída ou abra a captura no Wireshark.')
    if suffix == '.log':
        return ('Logs', ['sed', '-n', '1,100p', '--', str(path)],
                'Clique em Filtrar e agrupar e confira as linhas na saída.')
    if suffix in ENCODING_OPERATIONS:
        args = (['xxd', '-r', '-p', str(path)] if suffix == '.hex'
                else ['base64', '--decode', '--', str(path)])
        return 'Codificação', args, 'Clique em Converter e confira o texto decodificado na saída.'
    if suffix in {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf'}:
        return ('Arquivos', ['exiftool', '-G1', '-a', '-s', str(path)],
                'Clique em Metadados ExifTool e confira comentários e campos do documento.')
    if suffix == '.http':
        return ('Arquivos', ['sed', '-n', '1,100p', '--', str(path)],
                'Clique em Ler resposta HTTP salva e confira o status, os cabeçalhos e o corpo.')
    return ('Arquivos', ['file', '--', str(path)],
            'Clique em Assinatura, hash e strings e confira o tipo, o hash e o texto imprimível.')


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


def analyze_ctf_text(text):
    if not text.strip():
        raise ValueError('Cole o enunciado ou uma pista.')
    if len(text) > 12000:
        raise ValueError('Cole até 12.000 caracteres por análise.')

    findings = {flag: 'texto original' for flag in FLAG_PATTERN.findall(text)}
    candidates = dict.fromkeys(re.findall(r'(?<![\w+/=-])[A-Za-z0-9+/_-]{8,4096}={0,2}(?![\w+/=-])', text))
    for candidate in candidates:
        operations = ['Base64 → texto']
        if re.fullmatch(r'(?:[0-9a-fA-F]{2})+', candidate):
            operations.append('Hexadecimal → texto')
        for operation in operations:
            try:
                value = candidate
                if operation == 'Base64 → texto':
                    value = candidate.replace('-', '+').replace('_', '/')
                    value += '=' * (-len(value) % 4)
                decoded = transform(value, operation)
            except (ValueError, binascii.Error):
                continue
            for flag in FLAG_PATTERN.findall(decoded):
                findings.setdefault(flag, f'{operation} ({candidate[:40]})')

    lines = ['Análise local do enunciado', '', 'Passos executados',
             '1. Busca por formatos de flag no texto original.',
             '2. Decodificação de trechos candidatos em Base64 e hexadecimal.', '', 'Resultado']
    lines.extend(f'{flag} — origem: {origin}' for flag, origin in findings.items())
    if not findings:
        lines.append('Nenhuma flag reconhecida no texto ou nos trechos decodificados.')
    return '\n'.join(lines)


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
    if companion.is_symlink() or not companion.is_file():
        raise ValueError('Não encontrei flag.txt ao lado de main.py. Importe o ZIP completo.')
    with companion.open(encoding='utf-8', errors='replace') as handle:
        note = handle.read(65_537)
    if len(note) > 65_536:
        raise ValueError('O arquivo flag.txt excede o limite de leitura do desafio XOR.')
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


def folder_ctf_candidates(source, stop, max_files):
    eligible_suffixes = {*ENCODING_OPERATIONS, '.txt', '.log', '.py', '.jpg', '.jpeg', '.elf', '.bin'}

    def candidates():
        for directory, subdirs, names in os.walk(source):
            if stop is not None and stop.is_set():
                raise InterruptedError('Análise interrompida.')
            subdirs[:] = [name for name in subdirs if name != '.git' and not (Path(directory) / name).is_symlink()]
            for name in names:
                path = Path(directory) / name
                try:
                    if not path.is_symlink() and path.is_file() and path.stat().st_size <= 8_000_000:
                        yield path
                except OSError:
                    continue

    def priority(path):
        return (path.name.lower() not in {'flag.txt', 'main.py'},
                path.suffix.lower() not in eligible_suffixes and bool(path.suffix),
                len(path.relative_to(source).parts), str(path).casefold())

    return nsmallest(max_files, candidates(), key=priority)


def docker_flag_provenance(dockerfile, data):
    """Trace direct copies and simple moves of a flag in the Docker build context."""
    context = dockerfile.parent.resolve()
    findings = []
    context_copied = False
    for line in data.decode('utf-8', errors='replace').splitlines():
        if not re.match(r'^\s*(?:COPY|RUN|FROM|WORKDIR)\s+', line, re.IGNORECASE):
            continue
        try:
            arguments = shlex.split(line)
            instruction = arguments[0].upper()
            if instruction in ('FROM', 'WORKDIR'):
                context_copied = False
                continue
            if instruction == 'COPY' and arguments[1:] == ['.', '.']:
                context_copied = True
                continue
            if instruction == 'RUN':
                if not context_copied or len(arguments) != 4 or arguments[1] != 'mv':
                    continue
                command = 'RUN mv'
                arguments = arguments[1:]
            else:
                command = 'COPY'
            if len(arguments) != 3 or arguments[1].startswith(('-', '/')):
                continue
            origin, destination = arguments[1:]
            if Path(origin).name.casefold() != 'flag.txt':
                continue
            local = (context / origin).resolve(strict=True)
            if not local.is_relative_to(context) or not local.is_file() or local.stat().st_size > 4096:
                continue
            content = local.read_text(encoding='utf-8', errors='replace')
        except (OSError, ValueError, RuntimeError):
            continue
        findings.append(f'{command} {shlex.quote(origin)} {shlex.quote(destination)}')
        if TEST_FLAG_PATTERN.fullmatch(content.strip()):
            findings.append('O arquivo de origem contém apenas uma flag de teste. A instrução preservaria esse valor na imagem local.')
        elif FLAG_PATTERN.search(content):
            findings.append('A origem contém um valor no formato de flag. A validade na plataforma depende da instância.')
        else:
            findings.append('A origem da cópia existe, mas não contém uma flag reconhecida.')
    return findings


def solve_local_ctf(value, stop=None, *, zip_password=None):
    """Analyze local evidence without running programs supplied by the challenge."""
    from ctf_importer import import_package

    if not str(value).strip():
        raise ValueError('Selecione um arquivo ou uma pasta.')
    source = Path(value).expanduser().resolve(strict=True)
    if not (source.is_file() or source.is_dir()):
        raise ValueError('Selecione um arquivo comum ou uma pasta.')
    reports = [f'Desafio: {source.name}']
    max_files = 32
    found_test_flag = False
    with tempfile.TemporaryDirectory(prefix='cyberpm-solve-') as directory:
        root = Path(directory)
        is_folder = source.is_dir()
        if is_folder:
            files = folder_ctf_candidates(source, stop, max_files + 1)
            reports.append('Examinei a pasta e as subpastas no local com Python (os.walk). Arquivos acima de 8 MB e links foram pulados.')
        elif zipfile.is_zipfile(source):
            try:
                package = import_package(source, root, limit_mib=64, stop=stop, zip_password=zip_password)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                raise ValueError(f'Não foi possível abrir o ZIP: {exc}') from exc
            files = sorted(package['root'] / name for name in package['files'])
            archive_step = f'Abri o ZIP com Python (zipfile) e extraí {len(files)} arquivo(s) em uma pasta temporária.'
            if package.get('opened_protected_entries'):
                archive_step += ' Abri as entradas protegidas com a senha informada.'
            reports.append(archive_step)
        else:
            files = [source]
            reports.append('Li o arquivo local selecionado.')
        for path in files[:max_files]:
            if stop is not None and stop.is_set():
                raise InterruptedError('Análise interrompida.')
            try:
                if path.stat().st_size > 8_000_000:
                    reports.append(f'{path.name}: arquivo acima do limite de 8 MB por item.')
                    continue
                data = path.read_bytes()
            except OSError:
                reports.append(f'{path.name}: não foi possível ler o arquivo.')
                continue
            report = None
            steps = []
            if path.name.casefold() == 'dockerfile':
                findings = docker_flag_provenance(path, data)
                if findings:
                    steps = ['Li o Dockerfile e rastreei as instruções que colocam o arquivo de flag na imagem.']
                    report = '\n'.join(findings)
            elif path.suffix.lower() == '.py' and b'dynamic_xor_encrypt' in data and b'gen_priv_key' in data:
                try:
                    report = dynamic_xor_report(path)
                    steps = ['Identifiquei no Python o algoritmo de XOR e li os dados de flag.txt.',
                             'Decodifiquei o Base64, testei as chaves previstas pelo código e reverti a ordem dos bytes.',
                             'Comparei os resultados imprimíveis com o formato da flag.',
                             'Código Python: base64.b64decode(...), c = (a | b) ** 2 e XOR byte a byte, seguido de [::-1].']
                except ValueError as exc:
                    report = str(exc)
            elif path.suffix.lower() in ENCODING_OPERATIONS:
                try:
                    report = transform(data.decode('ascii'), ENCODING_OPERATIONS[path.suffix.lower()])
                    steps = [f'Decodifiquei o arquivo usando {ENCODING_OPERATIONS[path.suffix.lower()]}.']
                    steps.append('Código Python: bytes.fromhex(...)' if path.suffix.lower() == '.hex'
                                 else 'Código Python: base64.b64decode(..., validate=True)')
                except ValueError as exc:
                    report = f'Falha ao decodificar: {exc}'
            elif data.startswith(b'\x7fELF'):
                flags = dict.fromkeys(flag for match in ELF_TEXT_WORDS.finditer(data)
                                      for flag in FLAG_PATTERN.findall(match[0][::4].decode('ascii')))
                report = ('Flags encontradas em palavras de 32 bits no ELF\n' + '\n'.join(flags)
                          if flags else elf_xor_flag(path))
                steps = ['Identifiquei a assinatura ELF e analisei os bytes do executável.']
                if flags:
                    steps.append('Reconstruí os caracteres armazenados em palavras de 32 bits e conferi o formato da flag.')
                    steps.append('Código Python: match[0][::4].decode("ascii") para ler um byte de cada palavra.')
                elif report:
                    steps.append('Li a rotina revelar_flag, reconstruí os blocos de bytes e apliquei o XOR observado.')
                    steps.append('Comando: ' + shlex.join(['objdump', '-d', '-Mintel', '--disassemble=revelar_flag', './' + path.name]))
            elif data.startswith(b'\xff\xd8\xff'):
                password = re.search(rb'Senha\s*:\s*([^\s\x00]+)', data[:65536], re.IGNORECASE)
                if password:
                    steps = ['Identifiquei a assinatura JPEG e encontrei uma senha nos metadados.']
                    report = extract_ctf_image(path, password.group(1).decode('ascii', errors='replace'), root, steps)
            if not report:
                report = file_report(path)
                steps.append('Calculei o hash e procurei texto imprimível no arquivo.')
                steps.append('Código Python: hashlib.sha256() e busca por sequências de caracteres ASCII imprimíveis.')
            if TEST_FLAG_PATTERN.search(report):
                found_test_flag = True
                report = TEST_FLAG_PATTERN.sub('[flag de teste omitida]', report)
                steps.append('Identifiquei um valor de teste, sem evidência da flag da instância do desafio.')
            steps.append('Encontrei um texto no formato de flag nesta saída.' if FLAG_PATTERN.search(report)
                         else 'A saída deste arquivo não revelou uma flag reconhecida.')
            numbered = '\n'.join(f'{index}. {step}' for index, step in enumerate(steps, 1))
            reports.append(f'{path.name}\nPassos executados\n{numbered}\n\nResultado\n{report}')
        if len(files) > max_files:
            reports.append(f'Análise limitada a {max_files} arquivos. Há outros itens na origem.')
    result = '\n\n'.join(reports)
    if not FLAG_PATTERN.search(result):
        summary = ('A evidência contém uma flag de teste. A flag da instância não foi encontrada.'
                   if found_test_flag else 'Nenhuma flag reconhecida. Confira as pistas abaixo.')
        result = summary + '\n\n' + result
    return result


def ctf_lab_address_url(value):
    url = target_url(value if '://' in value else 'http://' + value.strip())
    parts = urlsplit(url)
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError as exc:
        raise ValueError('Informe o endereço IP do laboratório, seguido da porta se houver.') from exc
    if address.is_unspecified or address.is_multicast:
        raise ValueError('Informe o IP de uma instância do laboratório.')
    return url


def elf_xor_flag(path):
    objdump = shutil.which('objdump')
    if not objdump:
        return None
    try:
        code = subprocess.run([objdump, '-d', '-Mintel', '--disassemble=revelar_flag', str(path)],
                              capture_output=True, text=True, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    stack = {}
    accumulator = None
    for line in code.splitlines():
        literal = re.search(r'\bmovabs\s+rax,0x([0-9a-f]+)', line)
        if literal:
            accumulator = int(literal[1], 16)
        store = re.search(r'\bmov\s+(BYTE|WORD|DWORD|QWORD) PTR \[rbp-0x([0-9a-f]+)\],(0x[0-9a-f]+|rax)\s*$', line)
        if not store:
            continue
        value = accumulator if store[3] == 'rax' else int(store[3], 16)
        if value is None:
            continue
        width = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8}[store[1]]
        if value >= 1 << (8 * width):
            continue
        offset = -int(store[2], 16)
        stack.update((offset + index, byte) for index, byte in enumerate(value.to_bytes(width, 'little')))
    clear = bytearray()
    loops = re.findall(r'movzx\s+eax,BYTE PTR \[rbp\+rax\*1-0x([0-9a-f]+)\][^\n]*\n[^\n]*\bxor\s+eax,0x([0-9a-f]{1,2})\b', code)
    for address, key in loops:
        offset = -int(address, 16)
        while stack.get(offset, 0):
            clear.append(stack[offset] ^ int(key, 16))
            offset += 1
    flag = FLAG_PATTERN.search(clear.decode('ascii', errors='replace'))
    return f'Flag recuperada da rotina revelar_flag: {flag[0]}' if flag else None


def extract_ctf_image(path, password, root, steps):
    tool = shutil.which('steghide')
    if not tool:
        return 'A imagem contém uma senha nos metadados. Steghide precisa estar instalado para testar a extração.'
    with tempfile.TemporaryDirectory(dir=root) as directory:
        output = Path(directory) / 'evidencia'
        try:
            subprocess.run([tool, 'extract', '-sf', str(path), '-p', password, '-xf', str(output)],
                           capture_output=True, timeout=10, check=True)
        except (OSError, subprocess.SubprocessError):
            return 'A imagem contém uma senha nos metadados, mas o Steghide não conseguiu extrair o conteúdo.'
        steps.append('Usei Steghide para extrair o conteúdo oculto do JPEG com a senha dos metadados.')
        steps.append('Comando: ' + shlex.join(['steghide', 'extract', '-sf', './' + path.name,
                                               '-p', '<senha dos metadados>', '-xf', 'evidencia']))
        if zipfile.is_zipfile(output):
            steps.append('Identifiquei um ZIP no conteúdo extraído e tentei abrir suas entradas com a mesma senha.')
            try:
                with zipfile.ZipFile(output) as archive:
                    members = [item for item in archive.infolist() if not item.is_dir()]
                    texts = []
                    for item in members[:32]:
                        if item.file_size > 64_000:
                            continue
                        with archive.open(item, pwd=password.encode('ascii')) as handle:
                            texts.append(f'{item.filename}\n' + handle.read(64_000).decode('utf-8', errors='replace'))
                    return 'Conteúdo do ZIP oculto\n' + '\n\n'.join(texts)[:24000]
            except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile):
                return 'Foi encontrado um ZIP oculto, mas a senha dos metadados não abriu seu conteúdo.'
        with output.open('rb') as handle:
            data = handle.read(2_000_000)
        return 'Conteúdo extraído da imagem\n' + data.decode('utf-8', errors='replace')[:24000]


def read_http_evidence(value):
    path = Path(local_file(value))
    with path.open('rb') as source:
        data = source.read(2_000_001)
    return data


def parse_http_response(data):
    if len(data) > 2_000_000:
        raise ValueError('Use uma resposta HTTP com até 2 MB.')
    parts = re.split(rb'\r?\n\r?\n', data, maxsplit=1)
    lines = parts[0].decode('iso-8859-1').splitlines()
    if not lines or not re.match(r'^HTTP/\d(?:\.\d)?\s+\d{3}\b', lines[0]):
        raise ValueError('O arquivo deve começar com uma linha de resposta, como HTTP/1.1 200 OK.')
    return lines[0], lines[1:], parts[1] if len(parts) == 2 else b''


def http_file_report(value):
    status, headers, data = parse_http_response(read_http_evidence(value))
    body = data.decode('utf-8', errors='replace')
    return ('STATUS\n'+status+'\n\nCABEÇALHOS\n'+'\n'.join(headers)+
            '\n\nCORPO DA RESPOSTA\n'+body+
            '\n\nDica: cabeçalhos ficam antes da primeira linha em branco. '
            'No desafio Cabeçalho suspeito, examine X-Lab-Trace.')


def object_access_review(allowed_response, restricted_response):
    try:
        allowed_status, _, allowed_body = parse_http_response(allowed_response)
    except ValueError as exc:
        raise ValueError(f'Conta autorizada. {exc}') from exc
    try:
        restricted_status, _, restricted_body = parse_http_response(restricted_response)
    except ValueError as exc:
        raise ValueError(f'Conta restrita. {exc}') from exc
    restricted_code = int(restricted_status.split()[1])
    if not 200 <= int(allowed_status.split()[1]) < 300:
        observation = 'A resposta da conta autorizada não confirmou acesso. Confira a evidência de referência.'
    elif restricted_code in (401, 403, 404):
        observation = 'O status da resposta restrita é compatível com a recusa esperada.'
    elif 200 <= restricted_code < 300:
        observation = 'A resposta restrita retornou sucesso. Confira se o corpo contém dados do objeto protegido.'
    else:
        observation = 'A resposta restrita é inconclusiva. Confira se houve redirecionamento ou erro.'
    comparison = 'iguais' if allowed_body == restricted_body else 'diferentes'
    return (
        'REVISÃO DE CONTROLE DE ACESSO AO OBJETO · IDOR/BOLA\n\n'
        'Regra esperada: a conta autorizada pode acessar o objeto; a conta restrita deve receber uma recusa.\n\n'
        f'Conta autorizada: {allowed_status} · {len(allowed_body)} bytes de corpo\n'
        f'Conta restrita: {restricted_status} · {len(restricted_body)} bytes de corpo\n'
        f'Os corpos são {comparison} na comparação byte a byte.\n\n'
        f'{observation}\n'
        'Confirme que as respostas correspondem ao mesmo objeto, à mesma operação e às contas indicadas. '
        'O status e o tamanho dos corpos, por si só, são insuficientes para confirmar IDOR/BOLA.'
    )


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
