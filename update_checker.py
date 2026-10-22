"""Atualização automática do Cyberpm usando releases oficiais do GitHub."""
import os
import re
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = 'Luistn/Cyberpm'
RELEASE_TAG = r'v\d+\.\d+(?:\.\d+)?'


def display_version(base):
    """Keep the public version separate from a legacy-compatible release tag."""
    base = Path(base)
    release = (base / 'VERSION').read_text(encoding='utf-8').strip()
    try:
        info = json.loads((base / 'version_info.json').read_text(encoding='utf-8'))
        value = info.get('display_version', '')
        if info.get('release_version') == release and isinstance(value, str) and re.fullmatch(r'\d+\.\d+(?:\.\d+)?', value):
            return value
    except (OSError, ValueError, AttributeError):
        pass
    return release

def _version_tuple(value):
    try:
        parts = tuple(int(x) for x in str(value).lstrip('v').split('.')[:3])
        return parts + (0,) * (3 - len(parts))
    except (ValueError, TypeError):
        return (0, 0, 0)

def _git(base, *args):
    return subprocess.run(['git', '-C', str(base), *args], capture_output=True, text=True, timeout=90)

def install_release(base, tag):
    """Fail closed on dirty working trees, detached HEAD and divergent histories."""
    if not re.fullmatch(RELEASE_TAG, tag):
        print('[Atualizações] Tag inválida.'); return False
    if not (base / '.git').exists():
        print('[Atualizações] Instalação sem Git: atualização automática indisponível. Use a instalação manual da Release.')
        return False
    branch = _git(base, 'branch', '--show-current')
    if branch.returncode or branch.stdout.strip() != 'main':
        print('[Atualizações] Atualização automática requer a branch main. Nenhum arquivo foi alterado.')
        return False
    status = _git(base, 'status', '--porcelain', '--untracked-files=no')
    if status.returncode or status.stdout.strip():
        print('[Atualizações] Existem alterações locais. Salve-as antes de atualizar; nada foi alterado.')
        return False
    remote = _git(base, 'remote', 'get-url', 'origin')
    if remote.returncode or remote.stdout.strip().removesuffix('.git') not in (
            f'https://github.com/{REPO}', f'git@github.com:{REPO}',
            'https://github.com/Luistn/Pentest-cyberops', 'git@github.com:Luistn/Pentest-cyberops'):
        print('[Atualizações] O remote origin não corresponde ao repositório oficial.'); return False
    print(f'[Atualizações] Baixando tag oficial {tag}...')
    fetched = _git(base, 'fetch', '--no-tags', 'origin', f'refs/tags/{tag}:refs/tags/{tag}')
    if fetched.returncode:
        print('[Atualizações] Falha ao obter a tag:', fetched.stderr.strip()[:300]); return False
    version = _git(base, 'show', f'{tag}:VERSION')
    if version.returncode or version.stdout.strip() != tag[1:]:
        print('[Atualizações] A versão da tag não corresponde à release.'); return False
    # Release numbering can restart; Git ancestry must still move forward.
    ahead = _git(base, 'merge-base', '--is-ancestor', 'HEAD', f'{tag}^{{commit}}')
    if ahead.returncode:
        print('[Atualizações] A release não avança o histórico instalado. Nenhum arquivo foi alterado.')
        return False
    # A tagged release must be reachable by fast-forward; never reset user work.
    merged = _git(base, 'merge', '--ff-only', tag)
    if merged.returncode:
        print('[Atualizações] Não foi possível atualizar por fast-forward. Atualize manualmente.')
        print(merged.stderr.strip()[:300]); return False
    installed = subprocess.run(['bash', str(base / 'instalar.sh')], cwd=base)
    if installed.returncode:
        print('[Atualizações] Arquivos baixados, mas o instalador falhou. Verifique o terminal.')
        return False
    print(f'[Atualizações] Cyberpm atualizado para {tag}.', flush=True)
    return True

def latest_release():
    """Use the release API, with the official release redirect as fallback."""
    try:
        req = urllib.request.Request(f'https://api.github.com/repos/{REPO}/releases/latest',
            headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'Cyberpm-updater'})
        with urllib.request.urlopen(req, timeout=8) as response:
            tag = json.load(response).get('tag_name', '')
        if isinstance(tag, str) and re.fullmatch(RELEASE_TAG, tag):
            return tag
        raise ValueError('resposta sem tag de release válida')
    except Exception:
        print('[Atualizações] API indisponível; consultando a página oficial da release...', flush=True)
    req = urllib.request.Request(f'https://github.com/{REPO}/releases/latest',
                                 headers={'User-Agent': 'Cyberpm-updater'})
    with urllib.request.urlopen(req, timeout=8) as response:
        final_url = response.geturl()
    prefix = f'https://github.com/{REPO}/releases/tag/'
    if not final_url.startswith(prefix):
        raise ValueError('página oficial não indicou uma release')
    tag = final_url[len(prefix):]
    if not re.fullmatch(RELEASE_TAG, tag):
        raise ValueError('tag inválida na página oficial')
    return tag


def check_updates(base, interactive=False, force=False, automatic=None):
    base = Path(base)
    try:
        cfg = {}
        config = base / 'update_config.json'
        if config.exists():
            try:
                cfg = json.loads(config.read_text(encoding='utf-8'))
                if not isinstance(cfg, dict):
                    raise ValueError('formato inválido')
            except (ValueError, OSError):
                print('[Atualizações] Configuração inválida; usando repositório oficial.')
                cfg = {}
        if cfg.get('github_repo', REPO).strip().strip('/') != REPO:
            print('[Atualizações] Repositório não configurado como oficial; atualização não executada.')
            return 1 if force else 0
        current = (base / 'VERSION').read_text(encoding='utf-8').strip()
        print(f'[Atualizações] Verificando release oficial (instalada: v{current})...', flush=True)
        tag = latest_release()
        if _version_tuple(tag) == _version_tuple(current):
            print(f'[Atualizações] Cyberpm v{current} já está atualizado.', flush=True)
            return 0
        print(f'[Atualizações] Cyberpm {tag} disponível (instalada: {current}).', flush=True)
        if _version_tuple(tag) < _version_tuple(current):
            print('[Atualizações] Numeração da release alterada; a atualização só será aplicada se avançar o histórico Git.', flush=True)
        should_install = automatic if automatic is not None else cfg.get('auto_update', True)
        if should_install or force:
            print('[Atualizações] Instalando atualização automaticamente...', flush=True)
            if install_release(base, tag):
                print('[Atualizações] Reiniciando com a nova versão...', flush=True)
                os.execv(sys.executable, [sys.executable, str(base / 'cyberpm'), *sys.argv[1:]])
            print('[Atualizações] Atualização não concluída. Versão instalada preservada; veja o motivo acima.', flush=True)
            return 1 if force else 0
        if interactive and sys.stdin.isatty():
            answer = input('Deseja baixar e instalar a atualização agora? [s/N] ').strip().lower()
            if answer in ('s', 'sim', 'y', 'yes') and install_release(base, tag):
                os.execv(sys.executable, [sys.executable, str(base / 'cyberpm'), *sys.argv[1:]])
    except SystemExit:
        raise
    except Exception as exc:
        print(f'[Atualizações] Não foi possível atualizar: {type(exc).__name__}: {str(exc)[:200]}', flush=True)
        print('[Atualizações] Versão instalada preservada. Verifique a conexão, Tor/AnonSurf e acesso ao GitHub.', flush=True)
        return 1 if force else 0
    return 0
