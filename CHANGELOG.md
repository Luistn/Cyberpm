# Histórico de versões

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
