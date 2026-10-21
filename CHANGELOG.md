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