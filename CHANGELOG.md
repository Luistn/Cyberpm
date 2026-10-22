## v1.6.6 — Cyberpm 1.2, resultados PHP e copia real

- Destaca conclusao, motivo e proximo passo em portugues no Scan PHP.
- Explica acesso recusado (HTTP 401/403/429), versao oculta e cobertura inconclusiva sem afirmar ausencia de vulnerabilidade.
- Preserva codigos HTTP e erros por requisicao no JSON e nos detalhes.
- Corrige Copiar resultados, Ctrl+C e Ctrl+A, com confirmacao ou erro visivel.
- Remove substituicao global da area de transferencia por memoria interna e usa clipboard real: Tk no Kali e Win32 no Windows.
- Mantem exibicao 1.2 e compatibilidade com atualizacao automatica de clientes antigos.
- Validacao: 59 testes e 6 subtestes aprovados; inclui copia real, janela, resultado 403 simulado e atualizador legado. Nenhuma requisicao ao dominio da captura.

## v1.6.5 — Cyberpm 1.2, transicao automatica

- Publica tag tecnica v1.6.5 para clientes v1.6.4 e anteriores reconhecerem e instalarem esta atualizacao apenas ao chamar cyberpm.
- Mantem 1.2 como versao exibida da interface; cyberpm --versao mostra tambem a release tecnica 1.6.5.
- Inclui a integracao Scan PHP e o atualizador da versao 1.2.
- Dispensa git pull manual na transicao para instalacoes Git oficiais em main, sem alteracoes locais e com acesso ao GitHub.
- Valida a numeracao de exibicao contra VERSION para evitar rotulos antigos em releases futuras.
- Atualiza README, banner, instalador e guias de publicacao e release.
- Validacao: 53 testes e 6 subtestes aprovados, incluindo o codigo real do atualizador v1.6.4 nos caminhos API e fallback; sintaxe Bash do instalador validada.

## v1.2

- Adota a numeracao 1.2 solicitada para esta release, apos a serie anterior 1.6.x.
- Liga o botao Scan PHP ao php2shell.py atualizado da pasta, com janela propria e alvo preenchido.
- Permite acompanhar requisicoes, parar, copiar resultados e exportar JSON; upload_progress e opcional.
- Corrige caminhos relativos a paginas PHP e remove a funcao duplicada da interface.
- Aceita releases vMAJOR.MINOR e vMAJOR.MINOR.PATCH no atualizador automatico.
- Permite nova numeracao somente quando a release oficial avanca o historico Git; preserva alteracoes locais e recusa regressao de commits.
- Na migracao do atualizador antigo, execute git pull --ff-only e bash instalar.sh uma vez. Apos isso, cyberpm consulta e instala releases automaticamente ao abrir.

## v1.6.4

- Adiciona o botão Scan PHP com janela independente das fases da auditoria para CVE-2026-109618 e CVE-2026-109619.
- Permite informar até 50 URLs, iniciar, parar, acompanhar resultados, copiar e exportar JSON.
- Compara versões anunciadas nos cabeçalhos HTTP com o aviso oficial do PHP; versões ocultas ou ambíguas resultam em inconclusivo.
- Usa requisições HEAD com validação TLS, limite de 10 segundos por URL e sem seguir redirecionamentos.
- A triagem não executa exploits nem confirma exploração; correções por backport precisam de confirmação com o fornecedor.
- Validação: 7 testes locais de classificação, entradas, requisições e redirecionamentos aprovados; sintaxe Python validada. Interface gráfica sem validação visual neste ambiente.

## v1.6.3

- Exibe saída ao vivo dos scanners e preserva stdout/stderr nas evidências, incluindo Nuclei, Katana, GAU, Nmap e FFUF.
- Mostra as ferramentas previstas no início de cada fase e os comandos do executor compartilhado, com credenciais ocultadas.
- Limita tempo e tentativas das consultas crt.sh e GAU e melhora o diagnóstico de cobertura parcial.
- Habilita estatísticas do Nuclei, desativa repetições de requisições e reduz o limite padrão para 5 minutos (configurável).
- Adiciona botões Copiar valor e Copiar detalhes e preserva a seleção de texto no painel de segredos.
- Validação: sintaxe Bash e regressões locais de scanners, limites, interrupção e saída ao vivo aprovadas. Validação gráfica de cópia pendente neste ambiente.

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