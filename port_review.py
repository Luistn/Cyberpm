"""Review only TCP ports saved by the preceding authorized scan."""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


def inventory(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    host = data['host']
    if not isinstance(host, str) or host.startswith('-'):
        raise ValueError('host inválido')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('host inválido')
    ports = sorted({item['port'] for item in data['ports']
                    if type(item.get('port')) is int and 0 < item['port'] < 65536})
    return host, ports


def command(host, ports, folder):
    args = ['nmap', '-Pn', '-sT', '-sV', '--version-light', '-T3',
            '--max-retries', '1', '--host-timeout', '120s', '--script-timeout', '10s',
            '--script', 'banner,http-headers,ssl-cert,ssh-hostkey',
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
    host, available = inventory(path)
    selected = {int(value) for value in args.ports.split(',') if value} if args.ports else set(available)
    if not selected or not selected.issubset(available):
        raise ValueError('selecione apenas portas do inventário salvo')
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
        except OSError:
            print('[!] Não foi possível iniciar Nmap', flush=True)
            code = 1
    (folder / 'port_review_status.json').write_text(json.dumps({'host': host, 'ports': sorted(selected), 'exit_code': code}), encoding='utf-8')
    print('[·] Resultado salvo em ' + str(folder / 'port_review.txt'), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
