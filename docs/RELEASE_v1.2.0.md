# CyberOps v1.2.0

Esta versão amplia a auditoria de APIs e serviços, corrige a detecção de login e organiza evidências e diagnósticos no relatório HTML.

- Arjun, testssl.sh e Retire.js integrados, com instalação automática das dependências no Kali, respeitando a opção de desativar instalação.
- GET/OPTIONS em até oito candidatos API do host, incluindo rotas GET declaradas em OpenAPI; metadados e resultados incluídos no relatório.
- Botão lateral de portas descobertas, inventário persistente e revisão posterior de serviços, banners, HTTP, certificados e chaves públicas SSH.
- Login com campos e formato configuráveis, cookies, campos ocultos/CSRF e evidência explícita de sucesso. HTTP 200/302 deixa de ser interpretado como login válido. Senhas não são gravadas no log; bloqueios interrompem os testes.
- Arquivo único de exposições candidatas de dados sensíveis com valores mascarados, arquivo/linha e referência. Não coleta bases externas de senhas vazadas.
- Limpeza dos resultados locais do site selecionado, com confirmação e verificação de caminho.
- Limites de execução, duração/código das fases, redução de falsos positivos de SPA e correção dos falsos erros nas fases 16, 22 e 27.
- Atualização automática pelas releases oficiais, com reinício do programa e preservação de alterações locais.

Validação: 19 testes Python, regressões Bash e construção da interface passaram usando servidor HTTP local e dados fictícios. A instalação apt/npm e as ferramentas externas reais precisam de validação no Kali.

Para instalações anteriores, execute `cyberops --atualizar`, confirme com `s` e abra o programa novamente. A partir da v1.2.0, as próximas releases são instaladas automaticamente ao abrir `cyberops`. Atualização automática requer clone Git na branch main, origin oficial e código sem alterações locais.

Sem privilégio disponível para instalar ferramentas, execute `sudo -v` no terminal antes de `cyberops open`. Sessões gráficas com pkexec podem solicitar autenticação do sistema.
