"""Classify curl transport timings without inferring a remote vulnerability."""
import argparse
import json
from pathlib import Path


def classify(metrics, exit_code, base):
    fields = metrics.strip().splitlines()
    fields += [''] * max(0, 6 - len(fields))
    code, address = fields[:2]
    def number(index):
        try:
            return float(fields[index])
        except ValueError:
            return 0.0
    tcp, tls, first_byte = number(3), number(4), number(5)
    received = code.isdigit() and 100 <= int(code) < 600
    state = 'http_received' if received else 'transport_error'
    if not received:
        if exit_code in (5, 6):
            state = 'dns_error'
        elif exit_code == 28:
            state = ('response_timeout' if tls > 0 or (not base.startswith('https:') and tcp > 0)
                     else 'tls_timeout' if tcp > 0 and base.startswith('https:') else 'connection_timeout')
        elif exit_code == 7:
            state = 'connection_failed'
        elif exit_code in (35, 60):
            state = 'tls_error'
    messages = {
        'http_received': f'Resposta HTTP {code} recebida; transporte disponível. Isso não confirma acesso ao conteúdo nem vulnerabilidade.',
        'dns_error': 'Falha ao resolver nome do alvo ou proxy; fases web não podem ser avaliadas nesta conexão.',
        'tls_timeout': 'Conexão TCP observada, mas negociação TLS não terminou no prazo. Não houve resposta HTTP.',
        'response_timeout': 'Conexão estabelecida, mas resposta HTTP não chegou no prazo.',
        'connection_timeout': 'Timeout ao estabelecer conexão/TLS. Os tempos disponíveis não permitem atribuir a causa a Tor, firewall ou servidor.',
        'connection_failed': 'Conexão não estabelecida; confira a rota, o serviço e o proxy, se configurado.',
        'tls_error': 'Falha na negociação TLS; consultar stderr do curl.',
        'transport_error': 'Coleta de conexão inconclusiva; consultar stdout/stderr do curl.',
    }
    return {'base': base, 'state': state, 'web_available': received, 'http_status': code,
            'remote_ip': address, 'curl_exit': exit_code, 'tcp_seconds': tcp,
            'tls_seconds': tls, 'first_byte_seconds': first_byte, 'message': messages[state]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--metrics', required=True)
    parser.add_argument('--exit-code', type=int, required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    result = classify(Path(args.metrics).read_text(errors='replace'), args.exit_code, args.base)
    Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print('[·] Conectividade: '+result['message'], flush=True)
    if result['remote_ip']:
        print('[·] IP observado nesta conexão: '+result['remote_ip'], flush=True)
    return 0 if result['web_available'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
