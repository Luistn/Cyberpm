"""Explain observations from Nmap XML without treating inventory as exploitation."""
from pathlib import Path
import xml.etree.ElementTree as ET


def summarize(path, host, exit_code=0):
    lines = ['RESUMO DA REVISÃO DE PORTAS', 'Alvo solicitado: '+host,
             'Método: conexão TCP, identificação de serviços e scripts de metadados do Nmap.',
             'Evidência: '+str(path)]
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return '\n'.join(lines + ['INCONCLUSIVO: XML ausente ou incompleto; consulte o log de erro.',
                                   'Não foi possível avaliar vulnerabilidades nesta revisão.'])+'\n'
    finished = root.find('runstats/finished')
    partial = exit_code != 0 or finished is None or finished.get('exit') != 'success'
    if partial:
        lines.append('REVISÃO PARCIAL: a execução não terminou normalmente; resultados limitados.')
    ports = root.findall('host/ports/port')
    observed = 0
    for port in ports:
        state = port.find('state')
        if state is None or state.get('state') != 'open':
            continue
        observed += 1
        where = port.get('portid', '?')+'/'+port.get('protocol', '?')
        service = port.find('service')
        name = 'não identificado' if service is None else ' '.join(filter(None, (
            service.get('name'), service.get('product'), service.get('version'))))
        lines += ['', f'INFORMATIVO — {where}: {name}',
                  'Como achou: Nmap registrou estado open e a identificação acima.']
        scripts = {s.get('id'): s.get('output', '') for s in port.findall('script')}
        headers = scripts.get('http-headers', '')
        if 'cloudflare' in (name+' '+headers).lower():
            lines += ['Contexto: resposta identificada como proxy Cloudflare; não comprova acesso direto ao servidor de origem.',
                      'Correção: confira a política do proxy e as restrições de acesso à origem antes de alterar portas.']
        else:
            lines.append('Correção: compare a exposição com a política do projeto; restrinja serviços desnecessários a clientes autorizados.')
        if headers:
            location = next((line.strip() for line in headers.splitlines() if line.strip().lower().startswith('location:')), None)
            if location:
                lines.append('Observação HTTP: '+location[:500]+' (redirecionamento observado).')
            lines.append('Cabeçalhos: coleta de metadados; não confirma proteção completa nem exploração.')
        if 'ssl-cert' in scripts:
            lines.append('TLS: certificado coletado. Isso não valida todos os protocolos, cifras, confiança ou correspondência do nome.')
        for script in ('smtp-commands', 'imap-capabilities', 'pop3-capabilities'):
            if script in scripts:
                lines.append('E-mail: capacidades coletadas por '+script+'; autenticação e envio de mensagens não foram testados.')
        lines += ['Como reproduzir: selecione esta porta e execute novamente a revisão no mesmo alvo autorizado.',
                  'Exploração: nenhuma demonstrada por esta coleta de metadados.']
    if not observed:
        lines.append('Nenhuma porta aberta registrada no XML; isso não comprova ausência de serviços ou falhas.')
    lines += ['', 'CONCLUSÃO: nenhuma vulnerabilidade confirmada por esta revisão de metadados.',
              'Isto não significa que o alvo está seguro. Exige testes específicos da aplicação, autenticação e configuração.',
              'O resumo cobre somente os endereços/portas efetivamente examinados; outros IPs do domínio podem não ter sido testados.']
    return '\n'.join(lines)+'\n'
