"""Bounded adapters for optional Kali OSINT tools."""
import importlib.util
import shutil
import subprocess
import os
import sys
import tempfile
from contextlib import nullcontext
from datetime import datetime, timezone


def availability():
    return {'dig': bool(shutil.which('dig')), 'whois': bool(shutil.which('whois')),
            'subfinder': bool(shutil.which('subfinder')), 'sherlock': bool(shutil.which('sherlock')),
            'phonenumbers': importlib.util.find_spec('phonenumbers') is not None}


def install_missing(kind):
    deps = availability()
    packages = ([pkg for tool, pkg in [('dig', 'dnsutils'), ('whois', 'whois')] if not deps[tool]]
                if kind in ('E-mail', 'Domínio') else ['python3-phonenumbers'] if kind == 'Telefone' and not deps['phonenumbers'] else [])
    if kind == 'Domínio' and not deps.get('subfinder'):
        packages.append('subfinder')
    if kind == 'Usuário' and not deps.get('sherlock'):
        packages.append('sherlock')
    if not packages:
        return []
    command = ['apt-get', 'install', '-y', *packages]
    status = 'erro'
    if not sys.platform.startswith('linux') or not shutil.which('apt-get'):
        output = 'Instalação automática requer Kali/Debian com apt-get.'
    else:
        prefix = [] if os.geteuid() == 0 else ['pkexec'] if shutil.which('pkexec') else ['sudo', '-n']
        try:
            result = subprocess.run(prefix + command, capture_output=True, text=True,
                                    errors='replace', timeout=180, shell=False)
            status = 'concluído' if result.returncode == 0 else 'erro'
            output = (result.stdout + '\n' + result.stderr)[-50000:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = str(exc)
    return [{'tool': 'apt-get', 'status': status, 'output': output, 'command': command,
             'collected_at': datetime.now(timezone.utc).isoformat()}]


def email_domain(value):
    domain = value.rsplit('@', 1)[1].encode('idna').decode('ascii')
    labels = domain.split('.')
    if len(domain) > 253 or any(not label or len(label) > 63 or
            not all(c.isascii() and (c.isalnum() or c == '-') for c in label) or
            label.startswith('-') or label.endswith('-') for label in labels):
        raise ValueError('Domínio de e-mail inválido para consulta DNS/WHOIS.')
    return domain


def run_tools(report):
    """Return records; never mutate GUI state or invoke a command shell."""
    records = []
    def record(tool, status, output, command=None):
        records.append({'tool': tool, 'status': status, 'output': output,
                        'command': command, 'collected_at': datetime.now(timezone.utc).isoformat(),
                        'interpretation': 'Saída técnica; não confirma identidade ou titularidade.'})
    if report['type'] in ('E-mail', 'Domínio', 'Usuário'):
        if report['type'] == 'Usuário':
            import re
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', report['value']):
                raise ValueError('Nome de usuário inválido.')
            commands = [['sherlock', '--print-found', '--no-color', '--timeout', '5', report['value']]]
        else:
            domain = email_domain(report['value'] if report['type'] == 'E-mail' else 'query@' + report['value'])
            commands = [['dig', '+time=3', '+tries=1', domain, kind] for kind in ('MX', 'TXT', 'A', 'AAAA')]
            commands.append(['whois', domain])
            if report['type'] == 'Domínio':
                commands += [['dig', '+time=3', '+tries=1', domain, kind] for kind in ('NS', 'CAA', 'SOA')]
                commands.append(['dig', '+time=3', '+tries=1', '_dmarc.' + domain, 'TXT'])
                commands.append(['subfinder', '-d', domain, '-silent', '-timeout', '10', '-max-time', '1'])
        for command in commands:
            executable = shutil.which(command[0])
            if not executable:
                record(command[0], 'ausente', 'Instale a dependência Kali: ' + command[0], command)
                continue
            try:
                limit = 120 if command[0] == 'sherlock' else 75 if command[0] == 'subfinder' else 20
                work = tempfile.TemporaryDirectory(prefix='cyberops-osint-') if command[0] == 'sherlock' else nullcontext(None)
                with work as workdir:
                    result = subprocess.run([executable, *command[1:]], capture_output=True,
                                            text=True, errors='replace', timeout=limit, shell=False, cwd=workdir)
                output = (result.stdout + '\n' + result.stderr).strip()
                record(command[0], 'concluído' if result.returncode == 0 else 'erro',
                       output[:50000], command)
            except subprocess.TimeoutExpired as exc:
                partial = exc.stdout or b''
                if isinstance(partial, bytes): partial = partial.decode('utf-8', errors='replace')
                record(command[0], 'tempo esgotado', f'Limite de {limit} segundos atingido.\n' + partial[:50000], command)
            except OSError as exc:
                record(command[0], 'erro', str(exc), command)
    elif report['type'] == 'Telefone':
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone as phone_timezone
        except ImportError:
            record('phonenumbers', 'ausente', 'Instale: sudo apt install python3-phonenumbers')
            return records
        try:
            number = phonenumbers.parse(report['value'], None if report['value'].startswith('+') else 'BR')
            output = {'region_default': 'BR para números sem DDI explícito',
                      'e164': phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
                      'possible': phonenumbers.is_possible_number(number),
                      'valid': phonenumbers.is_valid_number(number),
                      'region': phonenumbers.region_code_for_number(number),
                      'description': geocoder.description_for_number(number, 'pt'),
                      'original_carrier': carrier.name_for_number(number, 'pt'),
                      'timezones': list(phone_timezone.time_zones_for_number(number)),
                      'limitation': 'Metadados locais; não informa localização atual, linha ativa ou operadora após portabilidade.'}
            import json
            record('phonenumbers', 'concluído', json.dumps(output, ensure_ascii=False, indent=2))
        except phonenumbers.NumberParseException as exc:
            record('phonenumbers', 'entrada inválida', str(exc))
    else:
        record('Cobertura', 'sem adaptador',
               'Nome e placa: use as fontes públicas no navegador. Não há base de identidade ou cadastro veicular integrada.')
    return records
