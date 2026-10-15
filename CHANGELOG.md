# Histórico de versões

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
- Identidade visual CyberOps (nome da classe e título); mantém nomes internos de arquivos para compatibilidade.
- Sem atualização silenciosa; exige Git e branch main.

## v1.1.0
- Login manual por navegador com reaproveitamento de cookies do host autorizado.
- Seleção de URLs de login descobertas no inventário local.
- Ajuda contextual para autenticação e força bruta.
- Correções de achados e da interface herdadas do pacote anterior.
- Repositório oficial configurado para checagem de versões.

## v1.0.0 — Primeira versão pública

- Identidade OP Cybernetica I e comando `cyberops`.
- Interface gráfica e execução via terminal.
- Reconhecimento WHOIS/RDAP/DNS e inventário técnico por fases.
- Logs e relatórios HTML com opção de envio ao Telegram.
- Instalador local, ajuda CLI e verificador opcional de releases do GitHub.
- README com captura real da interface e guias de instalação, Telegram e publicação.
