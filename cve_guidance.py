"""Contextual guidance from local Retire.js evidence; never executes a PoC."""
import json
from pathlib import Path
import re


def guidance(message, output_dir):
    ids=set(re.findall(r'CVE-\d{4}-\d+', message, re.I))
    if not ids or not output_dir:
        return ''
    path=Path(output_dir)/'29_js'/'retire.json'
    try:
        if path.stat().st_size > 8_000_000:
            return '\nContexto Retire.js: arquivo excede o limite de leitura; revise a evidência original.\n'
        data=json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return '\nContexto Retire.js indisponível. Identifique componente, versão e pré-requisitos no aviso oficial antes de montar uma reprodução.\n'
    lines=[]
    if not isinstance(data,dict) or not isinstance(data.get('data'),list):
        return '\nContexto Retire.js: formato não reconhecido; revise a evidência original.\n'
    for entry in data['data']:
        if not isinstance(entry,dict): continue
        for result in entry.get('results',[]):
            if not isinstance(result,dict): continue
            for vuln in result.get('vulnerabilities',[]):
                if not isinstance(vuln,dict): continue
                identifiers=vuln.get('identifiers',{})
                if not isinstance(identifiers,dict): continue
                cves=identifiers.get('CVE',[])
                if not isinstance(cves,list) or not ids.intersection(str(value).upper() for value in cves): continue
                lines += ['\n── CONTEXTO E REPRODUÇÃO ──',
                          f'Componente detectado: {result.get("component","?")} {result.get("version","?")}',
                          'Arquivo: '+str(entry.get('file','?')),
                          'Como achou: correspondência de conteúdo/versão do Retire.js; não executou exploração.',
                          'Descrição do catálogo: '+str(identifiers.get('summary','Não disponível'))[:1200],
                          'Faixa do catálogo: a partir de '+str(vuln.get('atOrAbove','não informado'))+' e abaixo de '+str(vuln.get('below','não informado')),
                          'Pré-requisitos: confirme a versão instalada, o ambiente (navegador/Node.js), o adaptador usado e qual entrada externa alcança a operação afetada.',
                          'Um bundle de navegador não comprova que o servidor utiliza o mesmo pacote.']
                if 'CVE-2025-27152' in ids and 'CVE-2025-27152' in cves and result.get('component')=='axios':
                    lines += ['Como reproduzir em laboratório (sem usar o domínio auditado):',
                              '1. Em um projeto isolado com a versão detectada do Axios, inicie dois servidores HTTP locais: 127.0.0.1:10001 e 127.0.0.1:10002. Registre caminho e cabeçalhos; use somente marcadores fictícios.',
                              '2. Configure axios.create({baseURL:"http://127.0.0.1:10001/", headers:{"X-Audit-Marker":"LAB-ONLY"}}).',
                              '3. Faça uma única chamada client.get("http://127.0.0.1:10002/").',
                              '4. Verifique se o segundo servidor recebeu a requisição e o marcador, apesar do baseURL apontar para o primeiro. Isso demonstra o comportamento da biblioteca no laboratório.',
                              '5. Para confirmar impacto na aplicação própria, prove que uma entrada controlável chega a esse argumento sem validação e com cabeçalhos relevantes. A simples presença do Axios não prova esse fluxo.',
                              'Como corrigir: o aviso original lista 1.8.2/0.30.0 para esta CVE. Consulte também os demais avisos da versão escolhida. Valide protocolo e origem da URL final com uma lista explícita de destinos permitidos; não use baseURL como barreira de segurança. Repita o teste com a validação implementada.',
                              'Exploração no alvo: não demonstrada. Não foram acessados serviços internos nem usadas credenciais reais.']
                else:
                    lines += ['Como reproduzir: consulte o PoC do aviso oficial e adapte-o a um projeto isolado com dados fictícios. Registre entrada, resultado esperado, resultado observado e versão corrigida. Esta evidência não contém uma reprodução específica validada para este caso.',
                              'Para avisos de DoS, confirme fluxo e limites em ambiente isolado; não tente travar o serviço auditado para validar uma detecção de versão.',
                              'Como corrigir: compare os intervalos afetados e versões corrigidas no aviso do fornecedor, atualize a dependência, gere novo bundle e repita a detecção e o teste aplicável.',
                              'Exploração no alvo: não demonstrada.']
                references=vuln.get('info',[])
                if isinstance(references,list):
                    lines += ['Referência do catálogo: '+value for value in references[:4] if isinstance(value,str) and value.startswith('https://')]
    return '\n'.join(lines)+'\n' if lines else '\nNenhum detalhe estruturado desta CVE no Retire.js local. Consulte a fonte indicada na evidência; não há PoC validado para este alvo.\n'
