"""Review only TCP ports saved by the preceding authorized scan."""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from database_review import DEFAULT_PORTS, check_tcp
from port_summary import summarize


def inventory(path):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data, dict) or not isinstance(data.get('ports'), list):
        raise ValueError('inventário inválido: esperado objeto com lista ports')
    host = data['host']
    if not isinstance(host, str) or host.startswith('-'):
        raise ValueError('host inválido')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('host inválido')
    ports = sorted({item['port'] for item in data['ports']
                    if isinstance(item, dict) and type(item.get('port')) is int and 0 < item['port'] < 65536})
    return host, ports


def command(host, ports, folder):
    scripts = ['banner', 'http-headers', 'ssl-cert', 'ssh-hostkey']
    if set(ports) & {25, 465, 587}:
        scripts.append('smtp-commands')
    if set(ports) & {143, 993}:
        scripts.append('imap-capabilities')
    if set(ports) & {110, 995}:
        scripts.append('pop3-capabilities')
    args = ['nmap', '-Pn', '-sT', '-sV', '--version-light', '-T3',
            '--max-retries', '1', '--host-timeout', '120s', '--script-timeout', '10s',
            '--script', ','.join(scripts),
            '-p', ','.join(map(str, ports)), '-oN', str(folder / 'port_review.txt'),
            '-oX', str(folder / 'port_review.xml')]
    if ':' in host:
        args.append('-6')
    return args + [host]


def install_nmap(folder):
    if not shutil.which('apt-get'):
        return False
    prefix = []
    if os.geteuid() != 0:
        if shutil.which('sudo') and subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode == 0:
            prefix = ['sudo', '-n']
        elif shutil.which('pkexec') and (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            prefix = ['pkexec']
        else:
            print('[!] Nmap ausente: execute sudo -v antes de abrir a interface', flush=True)
            return False
    with (folder / 'port_install.log').open('w') as log:
        try:
            subprocess.run(prefix + ['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', 'nmap'],
                           stdout=log, stderr=log, timeout=90, check=True)
        except (OSError, subprocess.SubprocessError):
            return False
    return bool(shutil.which('nmap'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--ports', default='')
    parser.add_argument('--no-install', action='store_true')
    args = parser.parse_args()
    path = Path(args.inventory).resolve()
    folder = path.parent
    try:
        host, available = inventory(path)
        selected = {int(value.strip()) for value in args.ports.split(',') if value.strip()} if args.ports else set(available)
        if not selected or not selected.issubset(available):
            raise ValueError('selecione apenas portas do inventário salvo')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'[!] Inventário/seleção inválido: {exc}', flush=True)
        return 2
    if not shutil.which('nmap') and (args.no_install or not install_nmap(folder)):
        print('[!] Nmap indisponível; teste não executado', flush=True)
        return 1
    for name in ('port_review.txt', 'port_review.xml'):
        (folder / name).unlink(missing_ok=True)
    print(f'[·] Revisão de serviços: {host} · portas {sorted(selected)}', flush=True)
    with (folder / 'port_review.stderr').open('w') as log:
        try:
            result = subprocess.run(command(host, sorted(selected), folder), stderr=log, timeout=135)
            code = result.returncode
        except subprocess.TimeoutExpired:
            print('[!] Revisão: limite de tempo atingido; evidências parciais preservadas', flush=True)
            code = 124
        except OSError as exc:
            print(f'[!] Não foi possível iniciar Nmap: {exc}', flush=True)
            code = 1
    if code:
        detail = (folder / 'port_review.stderr').read_text(encoding='utf-8', errors='replace').strip()
        print(f'[!] Nmap terminou com código {code}. ' + detail[-3000:], flush=True)
    (folder / 'port_review_status.json').write_text(json.dumps({'host': host, 'ports': sorted(selected), 'exit_code': code}), encoding='utf-8')
    summary = summarize(folder / 'port_review.xml', host, code)
    (folder / 'port_summary.txt').write_text(summary, encoding='utf-8')
    print(summary, flush=True)
    database_results = [check_tcp(host, engine, port) for engine, port in DEFAULT_PORTS.items() if port in selected]
    (folder / 'database_review.json').write_text(json.dumps(database_results, ensure_ascii=False, indent=2), encoding='utf-8')
    if database_results:
        print('[·] Diagnóstico TCP de bancos salvo em ' + str(folder / 'database_review.json'), flush=True)
    if (folder / 'port_review.txt').exists():
        print('[·] Resultado salvo em ' + str(folder / 'port_review.txt'), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
