"""Validate Nmap completion and preserve explicit and grouped port states."""
import argparse
from collections import Counter
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def inventory(path, host, exit_code=0):
    result = {'host': host, 'ports': [], 'states': {}, 'complete': False,
              'addresses': [], 'exit_code': exit_code, 'diagnostic': ''}
    try:
        root = ET.parse(path).getroot()
        if root.tag != 'nmaprun':
            raise ValueError('documento não é saída Nmap')
    except (OSError, ET.ParseError, ValueError) as exc:
        result['diagnostic'] = f'XML ausente/inválido: {exc}'
        return result
    finished = root.find('runstats/finished')
    hosts = root.findall('host')
    result['complete'] = (exit_code == 0 and finished is not None
                          and finished.get('exit') == 'success' and bool(hosts))
    states = Counter()
    for node in hosts:
        addresses = [a.get('addr') for a in node.findall('address')
                     if a.get('addrtype') in ('ipv4', 'ipv6') and a.get('addr')]
        result['addresses'].extend(addresses)
        for extra in node.findall('ports/extraports'):
            states[extra.get('state', 'unknown')] += int(extra.get('count', '0'))
        for port in node.findall('ports/port'):
            state = port.find('state')
            label = state.get('state', 'unknown') if state is not None else 'unknown'
            states[label] += 1
            if label != 'open' or port.get('protocol') != 'tcp':
                continue
            number = int(port.get('portid', '0'))
            if not 0 < number < 65536:
                continue
            service = port.find('service')
            name = '' if service is None else ' '.join(filter(None, (
                service.get('name'), service.get('product'), service.get('version'))))
            result['ports'].append({'port': number, 'service': name,
                                    'addresses': addresses,
                                    'reason': state.get('reason', '')})
    result['states'] = dict(states)
    if not states:
        result['complete'] = False
    result['diagnostic'] = ('Execução concluída; cobertura limitada às portas e endereços examinados.'
                            if result['complete'] else
                            'Execução inconclusiva/parcial: verifique nmap.exec.txt, nmap.stderr e nmap.stdout.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--xml', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--exit-code', type=int, default=0)
    args = parser.parse_args()
    result = inventory(args.xml, args.host, args.exit_code)
    folder = Path(args.out)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'scan_status.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    (folder / 'portas.txt').write_text(''.join(
        f"{row['port']}/tcp open {row['service']}\n" for row in result['ports']), encoding='utf-8')
    summary = [result['diagnostic'], 'Endereços examinados: '+(', '.join(result['addresses']) or 'indisponíveis'),
               'Estados de portas: '+(', '.join(f'{key}={value}' for key, value in result['states'].items()) or 'indisponíveis')]
    if result['states'].get('filtered') or result['states'].get('open|filtered'):
        summary.append('Portas filtradas: causa não determinada; não equivalem a portas fechadas.')
    (folder / 'resumo.txt').write_text('\n'.join(summary)+'\n', encoding='utf-8')
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
