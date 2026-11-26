"""Import user-selected CTF evidence or laboratory bundles into local storage."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import threading
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
import zipfile

from ctf_tools import target_url


CTF_LAB_HOST = 'ctf-lab-estudos-mwkq0dq4.hushedcrab131.chatgpt.site'
CTF_LAB_CATALOG = f'https://{CTF_LAB_HOST}/ctf-results.json'
CTF_LAB_MIRROR = 'https://raw.githubusercontent.com/Luistn/Cyberpm/main/docs/ctf-lab-results.json'


def ctf_lab_challenge_url(challenge_id):
    return f'https://{CTF_LAB_HOST}/?' + urlencode({'desafio': challenge_id})


def is_ctf_lab_url(url):
    try:
        parts = urlsplit(url.strip())
        return (parts.scheme == 'https' and parts.netloc.lower() == CTF_LAB_HOST
                and parts.path in ('', '/', '/ctf-results.json'))
    except ValueError:
        return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def import_ctf_lab_results():
    opener = build_opener(_NoRedirect)
    limit = 256 * 1024
    try:
        with opener.open(CTF_LAB_CATALOG, timeout=10) as response:
            raw = response.read(limit + 1)
    except OSError as site_error:
        try:
            with opener.open(CTF_LAB_MIRROR, timeout=10) as response:
                raw = response.read(limit + 1)
        except OSError as mirror_error:
            raise OSError(f'Catálogo indisponível no CTF Lab ({site_error}) e no GitHub ({mirror_error}).') from mirror_error
    if len(raw) > limit:
        raise ValueError('O catálogo do CTF Lab excede o tamanho permitido.')
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get('schema') != 'ctf-lab-results-v1':
        raise ValueError('Formato de catálogo do CTF Lab inválido.')
    entries = data.get('results')
    if not isinstance(entries, list) or not entries:
        raise ValueError('Nenhuma flag publicada no catálogo.')
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict)
                or not all(isinstance(entry.get(key), str) and entry[key].strip()
                           for key in ('id', 'title', 'category', 'flag', 'explanation'))
                or not re.fullmatch(r'CTF\{[^{}\s]{1,150}\}', entry['flag'])
                or entry['id'] in seen):
            raise ValueError('O catálogo contém um resultado inválido ou repetido.')
        seen.add(entry['id'])
    return entries


def safe_member(name):
    path = PurePosixPath(name.replace('\\','/'))
    if path.is_absolute() or '..' in path.parts or any(':' in part or '\0' in part for part in path.parts):
        raise ValueError(f'Caminho inválido no pacote: {name}')
    if os.name=='nt':
        reserved = {'CON','PRN','AUX','NUL'} | {f'{prefix}{number}' for prefix in ('COM','LPT') for number in range(1,10)}
        if any(part.rstrip(' .')!=part or part.split('.')[0].upper() in reserved for part in path.parts):
            raise ValueError(f'Nome de arquivo incompatível com Windows: {name}')
    if not path.parts:
        raise ValueError('Nome de arquivo vazio no pacote.')
    return Path(*path.parts)


def package_info(root):
    root = Path(root).resolve()
    children = list(root.iterdir())
    content = children[0] if len(children)==1 and children[0].is_dir() else root
    manifest = content/'ctf.json'
    data = {}
    if manifest.is_file():
        if manifest.stat().st_size > 1_000_000:
            raise ValueError('O manifesto ctf.json pode ter até 1 MB.')
        data = json.loads(manifest.read_text(encoding='utf-8-sig'))
        if not isinstance(data,dict):
            raise ValueError('ctf.json deve conter um objeto JSON.')
    for key in ('title','description','instructions','url'):
        if key in data and not isinstance(data[key],str):
            raise ValueError(f'O campo {key} de ctf.json deve ser texto.')
    commands = data.get('setup',[])
    if isinstance(commands,str):
        commands = [commands]
    if not isinstance(commands,list) or not all(isinstance(command,str) for command in commands):
        raise ValueError('setup deve ser um comando ou uma lista de comandos em texto.')
    url = target_url(data['url']) if data.get('url') else ''
    readme = ''
    for name in ('README.md','readme.md','README.txt','README','enunciado.md','enunciado.txt'):
        path = content/name
        if path.is_file():
            with path.open(encoding='utf-8-sig',errors='replace') as source:
                readme = source.read(1_000_000)
            break
    files = sorted(path for path in root.rglob('*') if path.is_file())
    if not commands and any((content/name).is_file() for name in ('compose.yaml','compose.yml','docker-compose.yml')):
        commands = ['docker compose up --build']
    return {'root':content, 'title':data.get('title') or content.name,
            'description':data.get('description',''), 'instructions':data.get('instructions',''),
            'readme':readme, 'url':url, 'setup':commands, 'files':files}


def zip_requires_password(source):
    if not zipfile.is_zipfile(source):
        return False
    with zipfile.ZipFile(source) as archive:
        return any(entry.flag_bits & 1 for entry in archive.infolist() if not entry.is_dir())


def import_package(source, destination=None, limit_mib=512, stop=None, *, zip_password=None):
    source = Path(source).expanduser().resolve(strict=True)
    limit = int(limit_mib)*1024*1024
    if limit <= 0:
        raise ValueError('O limite de extração deve ser maior que zero.')
    base = Path(destination) if destination else Path.home()/'.config'/'cyberpm'/'ctf-imports'
    base = base.expanduser().resolve()
    if source.is_dir() and base.is_relative_to(source):
        raise ValueError('Escolha a pasta do laboratório, sem incluir a pasta de destino das importações.')
    base.mkdir(parents=True,exist_ok=True)
    stop = stop or threading.Event()
    staging = Path(tempfile.mkdtemp(prefix='ctf-',dir=base)).resolve()
    written = 0
    opened_protected_entries = False

    def copy_stream(reader, target):
        nonlocal written
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as output:
            while True:
                if stop.is_set():
                    raise InterruptedError('Importação interrompida.')
                block = reader.read(65536)
                if not block:
                    break
                written += len(block)
                if written>limit:
                    raise ValueError('O conteúdo extraído excedeu o limite informado.')
                output.write(block)

    try:
        if source.is_dir():
            files = []
            total = 0
            for path in source.rglob('*'):
                if path.is_symlink() or getattr(path,'is_junction',lambda:False)():
                    raise ValueError('O pacote contém links simbólicos ou junções. Importe os arquivos do laboratório diretamente.')
                if path.is_file():
                    total += path.stat().st_size
                    files.append(path)
                    if len(files)>10000 or total>limit:
                        raise ValueError('O pacote excede o limite de tamanho ou de 10.000 arquivos.')
            if total>shutil.disk_usage(base).free:
                raise ValueError('Espaço em disco insuficiente para importar o laboratório.')
            for path in files:
                with path.open('rb') as reader:
                    copy_stream(reader,staging/path.relative_to(source))
                if path.stat().st_mode & 0o111:
                    (staging/path.relative_to(source)).chmod(0o755)
        else:
            with zipfile.ZipFile(source) as archive:
                entries = archive.infolist()
                total = sum(entry.file_size for entry in entries)
                if len(entries)>10000 or total>limit:
                    raise ValueError('O ZIP excede o limite de tamanho ou de 10.000 entradas.')
                if total>shutil.disk_usage(base).free:
                    raise ValueError('Espaço em disco insuficiente para extrair o laboratório.')
                targets = set()
                for entry in entries:
                    if entry.is_dir() and entry.filename in ('.','./','.\\'):
                        continue
                    path = safe_member(entry.filename)
                    if stat.S_ISLNK(entry.external_attr>>16):
                        raise ValueError('Links simbólicos dentro do ZIP não são importados.')
                    target = (staging/path).resolve()
                    if not target.is_relative_to(staging) or target==staging:
                        raise ValueError('O arquivo aponta para fora da pasta de importação.')
                    key = str(target).casefold()
                    if key in targets:
                        raise ValueError('O ZIP contém caminhos repetidos ou que diferem apenas em maiúsculas.')
                    targets.add(key)
                    if entry.is_dir():
                        target.mkdir(parents=True,exist_ok=True)
                    else:
                        protected = bool(entry.flag_bits & 1)
                        if protected and not zip_password:
                            raise ValueError('Informe a senha para abrir o ZIP protegido.')
                        password = zip_password.encode('utf-8') if protected else None
                        try:
                            with archive.open(entry, pwd=password) as reader:
                                copy_stream(reader,target)
                        except NotImplementedError as exc:
                            raise ValueError('O método de criptografia ou compressão deste ZIP não é suportado.') from exc
                        except RuntimeError as exc:
                            if not protected:
                                raise
                            raise ValueError('O ZIP está protegido. Confira a senha e tente novamente.') from exc
                        opened_protected_entries |= protected
                        if entry.external_attr>>16 & 0o111:
                            target.chmod(0o755)
        if stop.is_set():
            raise InterruptedError('Importação interrompida.')
        info = package_info(staging)
        if opened_protected_entries:
            info['opened_protected_entries'] = True
        if info['title']==staging.name:
            info['title'] = source.stem if source.is_file() else source.name
        return info
    except BaseException:
        # Only remove the unique directory created by this invocation.
        if staging.parent==base and staging!=base:
            shutil.rmtree(staging)
        raise


def write_template(path):
    manifest = {'title':'Exemplo de importação',
                'description':'Pacote de treino para conferir enunciado, arquivos e preparação.',
                'url':'http://127.0.0.1:8765/',
                'setup':['python3 -m http.server 8765 --bind 127.0.0.1']}
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,delete=False) as output:
            temporary = Path(output.name)
            with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('ctf.json',json.dumps(manifest,ensure_ascii=False,indent=2))
                archive.writestr('README.md','# Laboratório de exemplo\n\nLeia evidencia.txt. '
                                 'Para abrir a página local, execute o comando de preparação na pasta importada.\n')
                archive.writestr('evidencia.txt','Arquivo de teste para abrir nas ferramentas do Cyberpm.\n')
                archive.writestr('index.html','<!doctype html><meta charset="utf-8"><h1>Laboratório local de exemplo</h1>')
        os.replace(temporary,destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
