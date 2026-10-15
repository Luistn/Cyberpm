"""Bounded database connectivity diagnostics and read-only SQLite checks."""
import argparse
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import time

DEFAULT_PORTS = {'mysql': 3306, 'postgresql': 5432, 'sqlserver': 1433, 'mongodb': 27017}


def explain(result):
    """Keep observations separate from unverified security conclusions."""
    sqlite = result['engine'] == 'sqlite'
    result['classification'] = 'diagnóstico; vulnerabilidade não confirmada'
    result['where'] = result.get('file') if sqlite else {'host': result['host'], 'port': result['port']}
    result['method'] = ('SQLite em mode=ro, query_only e PRAGMA quick_check(1), sem ler tabelas'
                        if sqlite else 'Uma conexão TCP, fechada imediatamente, sem credenciais ou comandos SQL')
    result['evidence'] = {'status': result['status'], 'error_code': result.get('error_code')}
    result['reproduce'] = ({'engine': 'sqlite', 'file': result['file']}
                           if sqlite else {key: result[key] for key in ('engine', 'host', 'port')})
    result['exploitation'] = 'Nenhuma exploração demonstrada por este diagnóstico.'
    if result['status'] == 'tcp_accessible':
        result['remediation'] = ('Confira se este cliente deveria alcançar o banco. Se não, restrinja bind/listen '
                                 'e firewall a clientes autorizados; revise autenticação, permissões e TLS no servidor.')
    elif result['status'] == 'ok':
        result['remediation'] = 'Integridade básica aprovada; revise permissões/ACLs, backups e exposição do arquivo.'
    elif result['status'] == 'integrity_issue':
        result['remediation'] = ('Preserve uma cópia e os arquivos WAL associados antes de agir; '
                                 'investigue armazenamento e restaure um backup validado em ambiente separado.')
    elif sqlite:
        result['remediation'] = 'Confira formato, permissões e bloqueios do arquivo; consulte error_code antes de alterar o banco.'
    else:
        result['remediation'] = 'Confira DNS, endereço, porta, serviço em execução, rota e regras de firewall para o cliente autorizado.'
    return result


def check_tcp(host, engine, port=None, timeout=3):
    port = DEFAULT_PORTS[engine] if port is None else port
    if not host or host.startswith('-') or not 1 <= port <= 65535:
        raise ValueError('host ou porta inválido')
    result = {'engine': engine, 'host': host, 'port': port,
              'scope': 'Conectividade TCP; não confirma protocolo, TLS ou permissões.'}
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result['status'] = 'tcp_accessible'
    except socket.gaierror:
        result['status'] = 'dns_error'
    except (TimeoutError, socket.timeout):
        result['status'] = 'timeout'
    except ConnectionRefusedError:
        result['status'] = 'connection_refused'
    except OSError as exc:
        result['status'] = 'network_error'
        result['error_code'] = exc.errno
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return explain(result)


def check_sqlite(filename, timeout=3):
    path = Path(filename).resolve(strict=True)
    if not path.is_file():
        raise ValueError('SQLite exige um arquivo existente')
    result = {'engine': 'sqlite', 'file': str(path),
              'scope': 'Leitura local; não verifica exposição HTTP ou ACLs do Windows.'}
    if os.name == 'posix':
        mode = stat.S_IMODE(path.stat().st_mode)
        result['posix_mode'] = oct(mode)
        result['accessible_to_others'] = bool(mode & 0o007)
    deadline = time.monotonic() + timeout
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', timeout=timeout, uri=True)
        connection.execute('PRAGMA query_only=ON')
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        rows = connection.execute('PRAGMA quick_check(1)').fetchmany(1)
        result['status'] = 'ok' if rows == [('ok',)] else 'integrity_issue'
    except sqlite3.Error as exc:
        # Do not include database content, schema or arbitrary driver messages.
        result['status'] = 'sqlite_error'
        result['error_code'] = getattr(exc, 'sqlite_errorname', 'SQLITE_ERROR')
    finally:
        if connection is not None:
            connection.close()
    return explain(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True, choices=[*DEFAULT_PORTS, 'sqlite'])
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--file')
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 0 < args.timeout <= 30:
        parser.error('--timeout deve ser maior que zero e no máximo 30 segundos')
    if args.engine == 'sqlite':
        if not args.file or args.host or args.port is not None:
            parser.error('SQLite exige --file; não use --host/--port')
    elif not args.host or args.file:
        parser.error('Banco de rede exige --host; não use --file')
    try:
        result = (check_sqlite(args.file, args.timeout) if args.engine == 'sqlite'
                  else check_tcp(args.host, args.engine, args.port, args.timeout))
        payload = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(payload + '\n', encoding='utf-8')
        print(payload)
        return 0 if result['status'] in ('ok', 'tcp_accessible') else 1
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Falha de configuração/arquivo: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
