# v1.7.23 - Cyberpm 1.25

- Analisa evidências CTF selecionadas com a IA configurada para sugerir categoria, ferramentas, etapas e respostas possíveis, sem executar arquivos.
- Mostra um indicador discreto de estado da IA e aguarda a pré-análise antes de liberar a importação; em caso de falha, permite continuar manualmente.
- Inclui um terminal GDB interativo para inspecionar executáveis ELF e compartilha o contexto da sessão com o assistente sob demanda.
- Melhora a identificação e o destaque de respostas recuperadas pelo resolvedor XOR.
- Corrige o aviso de retorno em bloco `finally` no encerramento de tarefas.

# v1.7.22 - Cyberpm 1.24

- Busca commits oficiais novos de `main` ao abrir `cyberpm` e instala atualizações por fast-forward, preservando alterações locais.
- Encaminha automaticamente os pacotes CTF conhecidos para análise, com ações dedicadas ao XOR dinâmico, extração de imagem e análise GDB.
- Acrescenta o manual CTF sob demanda e o assistente DeepSeek contextual, ativados por atalhos.
- Atualiza automaticamente o lançador depois da instalação e reinicia com o código novo.

# v1.7.21 - Cyberpm 1.23

- Integra Vulnx, da ProjectDiscovery, como etapa obrigatória de inteligência de CVEs a partir das versões identificadas pelo Nmap.
- Inclui a etapa CVE nos perfis Rápido, Completo e Bug Bounty; selecionar CVEs também inclui Nmap automaticamente.
- Instala Vulnx pela distribuição oficial Go quando ausente e registra resultados, consultas e falhas em `10_cves/`.
- Permite limitar consultas, tempo total e revisar os CVEs correlacionados junto das evidências locais.
- Validação automatizada não executada nesta publicação.

# v1.7.20 - Cyberpm 1.22

- Corrige a varredura XSS com a flag `--workers` do Dalfox e habilita descoberta de parâmetros quando não há parâmetros conhecidos.
- Amplia a cobertura de API e inclui parâmetros GET opcionais de OpenAPI/Swagger nos candidatos a SQLmap e XSS.
- Prioriza parâmetros úteis no SQLmap, amplia a amostra e faz crawl GET limitado quando ainda não há parâmetros.
- Corrige o inventário de subdomínios e permite executar o perfil Bug Bounty em sequência nos hosts autorizados selecionados.
- Amplia os limites configuráveis de Nuclei, API, SQLmap e XSS; adiciona acesso a Achados na barra lateral.
- Validação automatizada não executada nesta publicação.

# v1.7.19 - Cyberpm 1.21

- Adiciona botão lateral Bug Bounty com seleção dedicada de fases, sem alterar o fluxo geral.
- Exige confirmação do escopo antes de iniciar esse fluxo e permite incluir inventário passivo WPScan para alvos WordPress.
- Atualiza o guia de uso e limites do fluxo Bug Bounty.
- Validação: 30 testes focados aprovados e compilação Python aprovada. A suíte completa no Windows teve 224 aprovações e 3 falhas de acesso à área de transferência.

## v1.7.18 - Cyberpm 1.20

- Torna o preenchimento com zeros opcional e mostra os extremos do intervalo na janela e ao exportar.

## v1.7.17 - Cyberpm 1.19

- Adiciona o modo Misturar dados de teste, com CSV em colunas e TXT intercalado.
- Limpa a resposta anterior do Shodan ao iniciar uma nova consulta ou busca.

## v1.7.16 - Cyberpm 1.18

- Exibe a lista completa, com opções de maiúsculas e minúsculas para letras e nomes.
- Destaca flags na saída de análises de evidência local do CTF.

## v1.7.15 - Cyberpm 1.17

- Abre as pesquisas do Shodan no navegador e orienta a exportação JSON.
- Adiciona listas de estudo com prévia e exportação TXT/CSV.
- Explica como escolher a aba pela evidência e salvar a saída do CTF.

## v1.7.14 - Cyberpm 1.16

- Usa um espelho oficial para importar o catálogo do CTF Lab quando o servidor principal recusa a conexão.
- Adiciona acesso ao navegador na janela de importação de CTFs externos.

## v1.7.13 - Cyberpm 1.15

- Importa o catálogo publicado do CTF Lab pela URL oficial.
- Destaca as flags, explica cada resultado e abre os desafios no navegador.

## v1.7.12 - Cyberpm 1.14

- Adiciona leitura de respostas HTTP salvas, separando status, cabeçalhos e corpo.
- Recupera chave XOR de um byte usando um prefixo conhecido, com script independente para o terminal.
- Monta URLs com parâmetros codificados para os testes manuais de SQL/XSS.
- Inclui exemplo HTTP e amplia as instruções das ferramentas correspondentes.
- Adiciona importação opcional de evidências, URLs e pacotes ZIP/pastas com README e manifesto ctf.json; encaminha os arquivos às ferramentas existentes.
- Validação: 211 testes Python e seis testes Bash aprovados.

## v1.7.11 - Cyberpm 1.13

- Substitui as abas superiores cinzas do CTF por oito botões coloridos, com indicação da ferramenta selecionada.
- Adiciona ajuda ao passar o mouse e instruções detalhadas de uso por missão, também no John e Hydra.
- Adiciona comandos e scripts copiáveis para execução independente no terminal do Kali, com os campos atuais.
- Cancela os temporizadores de atualização ao encerrar as janelas.
- Valida scripts independentes de conversão, logs e wordlists e argumentos com espaços e aspas.
- Validação: 196 testes Python e seis testes Bash aprovados. A aparência e os scanners no Kali precisam de validação nesse ambiente.

## v1.7.10 - Cyberpm 1.12

- Botões CTF com cores de alto contraste para executar, carregar exemplos, limpar e interromper.
- Exemplos opcionais e instruções de resultado esperado em todas as abas do CTF, John e Hydra.
- Servidor de aula em localhost para login, Nmap, cookies, SQL e XSS; arquivos temporários para capturas, metadados, hashes e logs.
- Gerador de wordlists com palavras-base, sufixos, variantes de maiúsculas, prévia, deduplicação e exportação em TXT.
- Atalhos para as janelas John e Hydra no guia do CTF.
- Validação: 188 testes Python e seis testes Bash aprovados. Ferramentas externas precisam de validação no Kali.

## v1.7.9 - Cyberpm 1.11

- Adiciona painel CTF com capturas TShark/Wireshark, conversões Base64/hexadecimal/XOR, assinaturas, SHA-256, strings e ExifTool.
- Inclui análise de logs, Nmap com portas personalizadas e execução direta de curl, SQLmap e Dalfox em URLs de laboratório.
- Integra orientações de estudo e instalação de ferramentas e SecLists no Kali.
- Validação: 179 testes Python, seis testes Bash e teste HTTP real do exercício de cookie administrativo.
- A execução real de Nmap, TShark, SQLmap e Dalfox precisa de validação no Kali; os testes cobrem a montagem dos comandos e a interface.

## v1.7.8 - Cyberpm 1.10

- Shodan com consulta IP e filtros de pais, estado e cidade.
- Brute force: validacao com uma senha, wordlist exclusiva e motivo detalhado de parada.
- Mantem janelas abertas ao selecionar arquivos e aplicar opcoes.
- Corrige interrupcao do John e atualiza testes.
- 170 testes Python e 6 testes shell aprovados; InternetDB verificado em consulta real.

## v1.7.7 - Cyberpm 1.9

- Menu lateral e ferramentas em janelas proprias.
- Reparo isolado de Playwright com --reparar-navegador.
- Explicacao do HTTP 405 e resumo do motivo de parada da lista.
- Ajustes no tamanho da janela de login e divisao do painel principal.

## v1.7.6 - Cyberpm 1.8

- Hydra com campos de alvo, servico, usuario, porta e wordlist, sem precisar montar comandos.
- Cria wordlists proprias (uma senha por linha, sem duplicatas), baixa listas por URL com wget e seleciona o arquivo ao concluir.
- Controla conexoes paralelas, intervalo e parada ao encontrar senha; inclui ajuda de cada servico e opcoes de formularios HTTP.
- Metadados de imagem via ExifTool: carregar arquivo, consultar EXIF/GPS/XMP/IPTC quando presentes e exportar JSON, preservando a imagem original. Inclui instalacao autenticada do ExifTool no Kali.
- Botoes coloridos para diferenciar ferramentas e acoes.

No Kali: execute `cyberpm` para atualizar automaticamente em clones Git oficiais na branch main. Se necessario: `sudo apt install hydra wget libimage-exiftool-perl`.

Validacao: testes de argumentos, wordlist, URLs, entradas invalidas, leitura simulada de metadados e abertura das janelas. Nenhuma tentativa real de login foi executada.

## v1.7.5 - Cyberpm 1.7, Hydra separado

- Adiciona botao Hydra com janela independente, selecao do executavel e argumentos.
- Exibe saida em tempo real e permite parar o processo.
- Distribui a nova janela pela atualizacao automatica existente no Kali.

## v1.7.4 - Cyberpm 1.6, ajustes da janela Sherlock

- Aumenta a janela Sherlock e destaca o botao Iniciar busca.
- Aceita nomes de usuario com ou sem @ inicial e melhora a mensagem de validacao.

## v1.7.3 - Cyberpm 1.5, atualizacao automatica e instalacao autenticada

- Guarda alteracoes locais rastreadas e arquivos nao rastreados em um stash antes de atualizar; mantem o backup disponivel sem reaplicar sobre a versao nova.
- Ao faltar John the Ripper ou Sherlock no Kali, explica qual pacote esta ausente e abre a autenticacao oficial do sistema para instalar.
- Inicia a busca Sherlock automaticamente depois da instalacao.
- Atualiza as notas e instrucoes da release.

## v1.7.2 - Cyberpm 1.4, atalhos de ferramentas e Sherlock

- Adiciona atalhos de Scan PHP, John the Ripper e Sherlock na fileira superior da interface.
- Adiciona janela Sherlock para buscar perfis publicos por nome de usuario, acompanhar e interromper a consulta e salvar resultados localmente.
- Organiza as ferramentas da secao ACOES em uma grade e compacta os botoes de ajuda.
- Documenta instalacao e uso do John e Sherlock, incluindo limites e localizacao dos resultados.

## v1.6.7 - Scan PHP com teste ativo (php2shell)

- Adiciona php2shell_active.py: stall multipart em duas fases, micro trigger e sonda de fixacao de sessao. Nada executa codigo; a cadeia 619 e opcional e exige offset do build.
- Corrige a sondagem de caminho: index.php, phpinfo.php, info.php e wp-login.php passam a ser resolvidos no diretorio da URL informada, com fallback na raiz.
- Corrige a coleta parcial: 404/405/410 nao marcam mais o scan inteiro como parcial.
- Novos vereditos: PRIMITIVA CONFIRMADA, INDICIO FORTE - WORKER INSTAVEL e EXECUCAO DE CODIGO CONFIRMADA.
- Janela: caixa de teste ativo, campos da cadeia 619 e resumo das sondas no relatorio.
- Corrige a mitigacao: memory_limit em valor real (nao -1), conforme o aviso do PHP.
## v1.6.6 â€” Cyberpm 1.2, resultados PHP e copia real

- Destaca conclusao, motivo e proximo passo em portugues no Scan PHP.
- Explica acesso recusado (HTTP 401/403/429), versao oculta e cobertura inconclusiva sem afirmar ausencia de vulnerabilidade.
- Preserva codigos HTTP e erros por requisicao no JSON e nos detalhes.
- Corrige Copiar resultados, Ctrl+C e Ctrl+A, com confirmacao ou erro visivel.
- Remove substituicao global da area de transferencia por memoria interna e usa clipboard real: Tk no Kali e Win32 no Windows.
- Mantem exibicao 1.2 e compatibilidade com atualizacao automatica de clientes antigos.
- Validacao: 59 testes e 6 subtestes aprovados; inclui copia real, janela, resultado 403 simulado e atualizador legado. Nenhuma requisicao ao dominio da captura.

## v1.6.5 â€” Cyberpm 1.2, transicao automatica

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

- Adiciona o botÃ£o Scan PHP com janela independente das fases da auditoria para CVE-2026-109618 e CVE-2026-109619.
- Permite informar atÃ© 50 URLs, iniciar, parar, acompanhar resultados, copiar e exportar JSON.
- Compara versÃµes anunciadas nos cabeÃ§alhos HTTP com o aviso oficial do PHP; versÃµes ocultas ou ambÃ­guas resultam em inconclusivo.
- Usa requisiÃ§Ãµes HEAD com validaÃ§Ã£o TLS, limite de 10 segundos por URL e sem seguir redirecionamentos.
- A triagem nÃ£o executa exploits nem confirma exploraÃ§Ã£o; correÃ§Ãµes por backport precisam de confirmaÃ§Ã£o com o fornecedor.
- ValidaÃ§Ã£o: 7 testes locais de classificaÃ§Ã£o, entradas, requisiÃ§Ãµes e redirecionamentos aprovados; sintaxe Python validada. Interface grÃ¡fica sem validaÃ§Ã£o visual neste ambiente.

## v1.6.3

- Exibe saÃ­da ao vivo dos scanners e preserva stdout/stderr nas evidÃªncias, incluindo Nuclei, Katana, GAU, Nmap e FFUF.
- Mostra as ferramentas previstas no inÃ­cio de cada fase e os comandos do executor compartilhado, com credenciais ocultadas.
- Limita tempo e tentativas das consultas crt.sh e GAU e melhora o diagnÃ³stico de cobertura parcial.
- Habilita estatÃ­sticas do Nuclei, desativa repetiÃ§Ãµes de requisiÃ§Ãµes e reduz o limite padrÃ£o para 5 minutos (configurÃ¡vel).
- Adiciona botÃµes Copiar valor e Copiar detalhes e preserva a seleÃ§Ã£o de texto no painel de segredos.
- ValidaÃ§Ã£o: sintaxe Bash e regressÃµes locais de scanners, limites, interrupÃ§Ã£o e saÃ­da ao vivo aprovadas. ValidaÃ§Ã£o grÃ¡fica de cÃ³pia pendente neste ambiente.

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
# v1.7.23 - Cyberpm 1.25

- Analisa evidências CTF selecionadas com a IA configurada para sugerir categoria, ferramentas, etapas e respostas possíveis, sem executar arquivos.
- Mostra um indicador discreto de estado da IA e aguarda a pré-análise antes de liberar a importação; em caso de falha, permite continuar manualmente.
- Inclui um terminal GDB interativo para inspecionar executáveis ELF e compartilha o contexto da sessão com o assistente sob demanda.
- Melhora a identificação e o destaque de respostas recuperadas pelo resolvedor XOR.
- Corrige o aviso de retorno em bloco `finally` no encerramento de tarefas.
