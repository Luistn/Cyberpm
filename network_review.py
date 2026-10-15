"""Linux network actions with before/after verification and link restoration."""
import argparse
import json
import re
import shutil
import subprocess
import sys


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)


def snapshot(interface):
    rows = json.loads(run(['ip', '-j', 'address', 'show', 'dev', interface]).stdout)
    if len(rows) != 1:
        raise ValueError('interface não encontrada')
    row = rows[0]
    return {'mac': row.get('address'), 'up': 'UP' in row.get('flags', []),
            'addresses': sorted(item['local'] for item in row.get('addr_info', []) if 'local' in item)}


def perform(action, interface):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface) or interface == 'lo':
        raise ValueError('selecione uma interface de rede válida, diferente de lo')
    required = ['ip', 'dhclient' if action == 'renew' else 'macchanger']
    for tool in required:
        if not shutil.which(tool):
            raise ValueError(f'ferramenta ausente: {tool}')
    before = snapshot(interface)
    if action == 'renew':
        run(['dhclient', '-r', interface])
        run(['dhclient', '-1', interface])
    else:
        try:
            run(['ip', 'link', 'set', 'dev', interface, 'down'])
            run(['macchanger', '-p' if action == 'restore' else '-r', interface])
        finally:
            if before['up']:
                run(['ip', 'link', 'set', 'dev', interface, 'up'])
    after = snapshot(interface)
    result = {'action': action, 'interface': interface, 'before': before, 'after': after}
    if action == 'renew':
        result['result'] = ('endereço local mudou' if before['addresses'] != after['addresses']
                            else 'DHCP executado; endereços locais permaneceram iguais')
    else:
        result['result'] = ('MAC mudou' if before['mac'] != after['mac'] else 'MAC permaneceu igual')
    result['note'] = 'Renovar DHCP não garante IP público diferente. Trocar MAC afeta a rede local.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('random', 'restore', 'renew'))
    parser.add_argument('interface')
    args = parser.parse_args()
    try:
        print(json.dumps(perform(args.action, args.interface), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Falha de rede: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
