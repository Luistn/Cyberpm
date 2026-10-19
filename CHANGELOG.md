# Histórico de versões

## v1.5.4 - SQLi por amostra e relatorio completo

- SQLi limitado a 5 URLs, 30s por URL e 90s no total em todos os modos.
- Exclui arquivos estaticos e evita repetir a mesma rota e parametros.
- Preserva inventario completo, amostra selecionada e cobertura parcial no relatorio.
- Remove cortes dos inventarios, logs de fase e diagnosticos no HTML das 29 fases.
- Links HTTP/HTTPS e rotas relativas de endpoints clicaveis no HTML.
- Selecao de texto independente da area de transferencia nas janelas.
- Testes de amostragem, relatorio completo, links escapados e copia repetida.

## v1.5.3 - Limite de tempo na etapa SQLi

- Limite total de 120s no modo Rapido e 300s no Completo/Profundo.
- Timeout por URL respeita o tempo restante da etapa.
- Parada apos tres timeouts consecutivos, preservando candidatos e evidencias.
- Aviso explicito de cobertura parcial e motivo registrado em interrupcao.txt.
- Testes de regressao com ferramentas simuladas, sem requisicoes externas.

## v1.5.2 — Correção da geração de relatório

- Removida importação local redundante que causava UnboundLocalError ao ler o diagnóstico de conexão no relatório HTML.
- Regressão inclui diagnóstico de conexão e inventário do domínio junto às evidências de API, portas e login.

## v1.5.1 — Correção do log vazio

- Campo de log agora é filho direto do frame que o exibe, com grade própria para texto e barras de rolagem, evitando sobreposição pelo frame.
- Divisão inicial reserva aproximadamente 70% da área ajustável para o log.
- Teste de regressão com painel mapeado, escrita, limpeza, novas mensagens e redimensionamento.

## v1.5.0 — Conectividade, evidências isoladas e log ajustável

- Painel de log maior, divisão vertical ajustável, rolagem horizontal e botão Limpar log sem excluir evidências.
- Pré-teste de transporte HTTP com classificação de falha DNS/conexão/TLS/resposta e tempos do curl.
- Fases web não executadas sem transporte; estados e contagens explícitos no relatório.
- Pastas novas por execução, evitando reutilizar resultados antigos.
- Propagação de falhas e resultados parciais de WPScan, ZAP, reconhecimento e crawl.
- Corrigida falha falsa de takeover quando não há CNAME.

## v1.4.5 — Atualização automática e explicação dos resultados

- Removido ASCII automático do terminal ao executar cyberpm.
- Abertura consulta e instala releases automaticamente, mesmo com preferência antiga de atualização manual.
- Consulta com timeout de 8s e fallback para a página oficial; falhas deixam de ser silenciosas.
- Relatório HTML com observação, impacto possível, reprodução controlada, correção, reteste e evidência para cada resultado.
- Orientações de SQLi/XSS mais específicas; não trata inventário ou respostas bloqueadas como falhas confirmadas.

## v1.4.4 — Evidências e cobertura das auditorias

- Nmap com saída XML, distinção de estados e detecção de execução incompleta.
- Registro de execução mesmo quando stdout/stderr estão vazios; diagnóstico do fallback TCP.
- Parser HTML de scripts e motivos de falha dos downloads JS visíveis.
- Nuclei recebe as URLs descobertas; erros e timeouts são sinalizados.
- SQLmap/Dalfox percorrem todas as URLs com parâmetros no modo Completo/Profundo, com logs separados e tabela de cobertura por URL.
- Não gera achados de cabeçalhos ausentes a partir de respostas HTTP de erro.
- Evita iniciar sem proxychains quando selecionado; bloqueia alterações de rede pela interface durante auditorias.
- Notificação inicial do Telegram: INÍCIO INVASÃO.
- Falhas de ferramentas mostram comando de reprodução, com credenciais substituídas por variáveis.
- Explicação específica de HSTS e respostas 403, também para achados antigos e relatório HTML.

## v1.4.3 — Controles compactos e Telegram sem ASCII

- Mensagem de início no Telegram sem ASCII; arte preservada na abertura local.
- Botões principais menores, mais finos e alinhados na mesma fileira de Iniciar teste.
- WPScan ao lado dos controles principais e desmarcado por padrão.
- JS/Segredos e Subdomínios lado a lado; Portas e Limpar resultados lado a lado.

## v1.4.2 — Layout principal e contraste

- Abertura com ASCII e botão Iniciar, sem frase abaixo da arte.
- Iniciar abre o painel principal de duas colunas, com o campo do site e todos os controles de auditoria.
- Restaurado o painel principal de duas colunas; removidas as telas extras e a importação manual de APIs.
- APIs descobertas e verificadas automaticamente na fase 7 em todos os modos, com prioridade para rotas encontradas em contratos e JavaScripts.
- Cores explícitas para todos os estados dos botões, com maior contraste.

## v1.4.1 — Reinício após a renomeação

- Adicionada ponte interna para atualizadores antigos que tentam reiniciar pelo arquivo `cyberops` após instalar Cyberpm.
- O comando instalado continua sendo somente `cyberpm`; argumentos da execução original são preservados.
- Documentada a recuperação imediata para instalações já atualizadas para v1.4.0.

## v1.4.0 — Cyberpm

- Sistema e comandos renomeados para Cyberpm (`cyberpm`, `cyberpm.sh`, `cyberpm_gui.py`).
- Repositório oficial e atualização apontam para `Luistn/Cyberpm`.
- Removida a consulta OSINT por nome, telefone, e-mail, usuário e placa, incluindo execução integrada e dependências específicas.
- Mantidos reconhecimento técnico de sites, subdomínios, WPScan e revisão de APIs.
- Ajustados layout dos controles e tamanho inicial da janela para telas menores.
- Central de auditoria com etapas reais agrupadas, consulta de resultados anteriores e validação manual com reprodução, impacto e hash de evidência.
- Importação de contrato OpenAPI/Swagger JSON e revisão limitada de rotas GET dentro da origem autorizada.
- Arte ASCII fornecida pelo usuário na tela inicial, terminal e mensagem de início no Telegram.
- Preservada a leitura das configurações antigas; comandos e caminhos novos documentados na migração.

Validação v1.4.0: 55 testes Python, regressões Bash e sintaxe aprovados. Layout verificado em três tamanhos de janela. Telegram testado com transporte simulado.

## v1.3.0 — OSINT, subdomínios, WordPress e revisão de APIs

- Aba OSINT independente, identificação de tipos e execução junto da auditoria de domínio, com acompanhamento nas fases e logs.
- Integrações com dig, whois, Subfinder, Sherlock e phonenumbers; instalação de dependências ausentes no Kali, respeitando a opção de não instalar.
- Consultas por nome e placa em fontes públicas no navegador, sem cadastro privado integrado.
- Registro de evidências e exportação JSON com histórico da sessão.
- Seleção de subdomínio autorizado para análise separada, sem reutilizar a sessão do host anterior.
- WPScan opcional na fase 3 com detecção passiva de plugins e temas; dados de vulnerabilidades dependem da API configurada.
- Logs coloridos por categoria.
- Revisão de respostas de APIs, categorias de campos sensíveis, erros internos e comparação de acesso autenticado/anônimo.
- CPFs fictícios inválidos somente em parâmetros GET declarados no OpenAPI; recuperação de senha sinalizada para validação controlada, sem envio automático.

Validação: 16 testes específicos e teste básico de integração da interface. Execução real das ferramentas e instalação no Kali ainda não validadas. A suíte completa apresentou anteriormente cinco problemas em testes de API/login neste ambiente; sintaxe Bash não pôde ser conferida devido a restrições de execução do Windows.

## v1.2.7 — Botões e ferramentas por fase

- Textos visíveis e ajuda usam Cyberpm no lugar da sigla anterior. O argumento antigo permanece aceito por compatibilidade, sem aparecer na ajuda.
- Botão Iniciar teste movido para antes e ao lado de Testar login, na seção Alvo.
- Dica ao passar o mouse sobre cada fase mostra as ferramentas previstas; não indica instalação ou execução confirmada.
- Capturas da interface e banner atualizados.

Validação: testes de release/relatório, sintaxe Bash, ajuda do comando e verificação da posição dos botões e dicas na interface local.


## v1.2.6 — Diagnósticos de fases, cópia e valores completos

Melhora o diagnóstico das fases 9, 12, 13, 20 e 23–26: mostra status, evidências, candidatos e limitações, inclusive quando não há resultados ou a consulta falha.

- Ctrl+C em textos/listas e botão Copiar log.
- CVEs listadas por ID único, referência e evidência; citação não comprova aplicabilidade nem exploração.
- Revisão básica de autorização ao final quando selecionada ou incluída pelas fases 27/28. Não valida automaticamente permissões entre contas.
- Modo Rápido respeitado pela GUI; seleção personalizada substitui o modo. Fases com erro aparecem como Falha/parcial e afetam o código final.
- Nomes das fases ajustados ao que realmente executam: inventário/heurística, orientação ou teste manual.
- Valores encontrados no inventário e em JS & Segredos são exibidos completos, incluindo senhas, tokens, chaves e CPF, conforme configuração solicitada. O HTML e o envio ao Telegram também podem incluir esses valores. Arquivos antigos não são reconstruídos; nomes contendo mascarados permanecem apenas por compatibilidade.

Validação com testes Python, sintaxe Bash, regressões HTTP simuladas e cópia de texto na GUI. Nenhum novo teste em alvo externo.


## v1.2.5 — Resultados da sessão e resumo de portas
- Remove carregamento automático da última pasta ao iniciar ou abrir Achados.
- Limpa lista, detalhes e referências de JS & Segredos quando não há análise atual.
- Acrescenta botão Achados no topo direito e alertas visuais/sonoros de término, interrupção e erro.
- Mostra resumo interpretado da revisão de portas no log e no relatório HTML, sem classificar portas abertas como vulnerabilidades confirmadas.
- Testes cobrem resultados antigos, proxy Cloudflare e evidências XML ausentes ou incompletas.

## v1.2.4 — Identificação de portas salvas
- O botão de portas identifica o host e a data do arquivo de inventário restaurado.
- A janela informa que o resultado é salvo, mostra o caminho da evidência e esclarece que abrir a janela não inicia varredura.
- Permite visualizar o inventário mesmo quando portas.txt está ausente.
- Teste de regressão verifica identificação do host e remoção do rótulo antigo sem inventário.

## v1.2.3 — Diagnósticos e ajuda de login
- Esclarece o teste de senhas de uma conta, configurações e critérios de sucesso; remove sugestão inventada de /api/login.
- Melhora validação e diagnóstico de erros da revisão de portas, com IPv6 e capacidades SMTP/IMAP/POP3.
- Adiciona diagnóstico TCP de bancos e integridade SQLite somente leitura, com evidência, reprodução e orientação.
- Corrige troca de MAC para tentar reativar a interface mesmo após erro; verifica estado antes/depois e explicita renovação DHCP local.
- Atualiza capturas reais, banner e documentação. Testes de rede usam simulações; operação real no Kali ainda requer validação.

## v1.2.2 — Janela de segredos fechada
- Corrige TclError ao concluir uma varredura depois de fechar a janela JS & Segredos.
- Verifica a existência dos widgets antes de atualizar ou mostrar detalhes e registra falhas pós-execução sem interromper o processamento dos eventos.

## v1.2.1 — Localização dos candidatos a segredo
- A tela JS & Segredos exibe o arquivo/linha antes ignorado, mantendo compatibilidade com auditorias anteriores.
- Novas auditorias incluem coluna e URL de origem para localizar candidatos em JavaScript minificado.
- O painel orienta a corrigir a origem no site e a revisar falsos positivos, preservando o valor mascarado.

## v1.2.0 — Auditoria organizada, APIs e revisão de portas
- Integra Arjun, testssl.sh e Retire.js com limites de tempo, evidências e instalação de dependências no Kali.
- Normaliza URLs do host autorizado e reduz falsos positivos de SPA, CVEs vazias e IDs numéricos.
- Requisições GET/OPTIONS de até oito candidatos API, incluindo rotas GET declaradas em OpenAPI, com metadados no relatório.
- Botão lateral de portas descobertas, inventário persistente e revisão de serviços TCP por Nmap após a varredura.
- Login configurável em JSON/formulário, cookies, campos ocultos/CSRF, marcadores de sucesso, limite de tentativas e interrupção em bloqueios.
- Inventário local de exposições de CPF, e-mails, senhas atribuídas, tokens e chaves; valores mascarados e localização da evidência.
- Atualização automática por release oficial, verificação do remote/tag e reinício do programa; preserva alterações locais.
- Limpeza local da pasta do site selecionado, com confirmação, verificação de caminho e bloqueio durante execução.
- Testes locais de transporte HTTP, autenticação, relatórios, atualização e fases Bash.

## v1.1.1 — Atualização com confirmação
- Ao iniciar pelo terminal, consulta a última Release e oferece instalação com confirmação.
- Atualização segura por tag oficial, sem sobrescrever alterações locais.
- Identidade visual Cyberpm (nome da classe e título); mantém nomes internos de arquivos para compatibilidade.
- Sem atualização silenciosa; exige Git e branch main.

## v1.1.0
- Login manual por navegador com reaproveitamento de cookies do host autorizado.
- Seleção de URLs de login descobertas no inventário local.
- Ajuda contextual para autenticação e força bruta.
- Correções de achados e da interface herdadas do pacote anterior.
- Repositório oficial configurado para checagem de versões.

## v1.0.0 — Primeira versão pública

- Identidade Cyberpm e comando `cyberpm`.
- Interface gráfica e execução via terminal.
- Reconhecimento WHOIS/RDAP/DNS e inventário técnico por fases.
- Logs e relatórios HTML com opção de envio ao Telegram.
- Instalador local, ajuda CLI e verificador opcional de releases do GitHub.
- README com captura real da interface e guias de instalação, Telegram e publicação.
