## v1.6.2

- Distingue execucao concluida com ressalvas de falha real do processo; preserva diagnosticos e codigo de saida para automacao.
- Corrige leitura TSV de segredos com valores completos, aspas, tabulacoes e quebras de linha.
- Exibe candidatos dos inventarios JavaScript e identificadores, sem duplicacoes, com arquivo, linha, coluna e origem.
- Atualiza o painel de segredos ao terminar as fases de coleta e inclui segredos encontrados no HTML.
- Limita a leitura local de CVEs a 30s, com corte externo de 35s, resumo permanente e diagnostico de cobertura parcial.
- Define limite padrao de 15 minutos para Nmap e Nuclei, preservando evidencias; limites continuam configuraveis.
- Validacao: 70 testes Python e regressoes Bash com ferramentas simuladas; nenhum teste no dominio externo.

## v1.6.1

- Corrige resolucao de URLs relativas a paginas como login.php e usa a origem para caminhos convencionais.
- Nmap recebe o host; Nuclei inclui a raiz da mesma origem e as paginas descobertas.
- Remove cortes totais padrao de Nmap/Nuclei, preservando Pular e limites opcionais NMAP_TIMEOUT/NUCLEI_TIMEOUT.
- Remove modo silencioso do WhatWeb que ocultava tecnologias identificadas.
- Amplia inventario de endpoints e metodos em JavaScript, formularios e OpenAPI.
- Adiciona plano explicito para GET, POST, PUT, PATCH e DELETE, com dados de teste, mesma origem e interrupcao por status inesperado.
- Documenta configuracao e inclui regressoes locais de URLs, inventario, metodos HTTP e controle de execucao.

## v1.6.0

- Adiciona camada de verificacao diferencial (`verify.py`): reexecuta achados com
  controle + payload, confirma em duas rodadas e atribui veredito e confianca.
- Adiciona esquema unico de achados (`findings.py`) com deduplicacao, severidade,
  mapeamento CWE/OWASP/CVSS e exportacao em JSON, TSV, Markdown e SARIF.
- Adiciona inventario e instalacao de ferramentas (`toolkit.py`).
- Adiciona descoberta unificada de ativos (`assets.py`).
- Relatorios agora distinguem achado confirmado de achado inconclusivo.