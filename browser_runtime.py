"""Isolate the Playwright Python package from broken system Node packages."""
import os
from pathlib import Path
import subprocess
import sys


def runtime_root():
    return Path.home() / '.config' / 'cyberpm' / 'browser-venv'


def runtime_python():
    root = runtime_root()
    return root / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def gui_python():
    root = runtime_root()
    python = runtime_python()
    return str(python) if python.is_file() and (root / '.ready').is_file() else sys.executable


def repair_browser():
    root = runtime_root()
    root.mkdir(parents=True, exist_ok=True)
    marker = root / '.ready'
    marker.unlink(missing_ok=True)
    env = os.environ.copy()
    env.pop('PLAYWRIGHT_NODEJS_PATH', None)
    python = str(runtime_python())
    steps = [
        [sys.executable, '-m', 'venv', str(root)],
        [python, '-m', 'pip', 'install', '--upgrade', 'playwright'],
        [python, '-m', 'playwright', 'install', 'chromium'],
        [python, '-c', 'import tkinter; from playwright.sync_api import sync_playwright; '
         'p = sync_playwright().start(); p.stop()'],
    ]
    try:
        for args in steps:
            result = subprocess.run(args, env=env)
            if result.returncode:
                print('Reparo nao concluido. No Kali, confirme python3-venv e python3-tk instalados. '
                      'Consulte o erro acima; dependencias nativas do Chromium podem ser necessarias.')
                return result.returncode
        marker.write_text('Playwright driver verified\n', encoding='utf-8')
    except OSError as exc:
        print(f'Falha no reparo: {exc}')
        return 1
    print('Navegador reparado em ambiente isolado. Feche o Cyberpm e execute cyberpm novamente.')
    return 0


def browser_error_message(error):
    message = str(error)
    if any(value in message.lower() for value in ('playwright', 'cli.js', 'module_not_found', 'executable doesn\'t exist')):
        return ('O Playwright ou o Chromium desta instalacao esta ausente ou incompleto. '
                'O erro ocorre antes de acessar o site.\n\n'
                'No terminal do Kali, execute:\n'
                'sudo apt install python3-venv python3-tk\n'
                'cyberpm --reparar-navegador\n\n'
                'Depois feche e abra o Cyberpm novamente.\n\nDetalhe: ' + message[:400])
    return message[:500]


def gui_environment():
    env = os.environ.copy()
    if gui_python() != sys.executable:
        env.pop('PLAYWRIGHT_NODEJS_PATH', None)
    return env
