## Cyberpm v1.2.3

Esta versão esclarece a configuração do teste de senhas de uma conta e melhora os diagnósticos de portas, bancos e rede.

- Teste de senhas com campos numerados, botão Como usar e explicação de formato, CSRF, marcador de sucesso e limites. Remove sugestão não verificada de `/api/login`.
- Revisão de portas com validação de inventários, erros visíveis, IPv6 e consulta de capacidades SMTP/IMAP/POP3.
- Diagnóstico reutilizável de conectividade para MySQL, PostgreSQL, SQL Server e MongoDB, além de integridade SQLite em modo somente leitura. Inclui localização, método, evidência, reprodução e orientação; não confirma SQL injection ou bypass.
- Operações de MAC com tentativa de restauração do estado ativo após falha. Renovação DHCP com estados antes/depois, sem prometer mudança de IP público.
- Banner e capturas reais da interface atualizados, sem configurações pessoais ou credenciais.

Validação: 30 testes Python, verificações de sintaxe Bash e regressões shell aprovados. Testes de rede usam simulações; alteração real de MAC/IP e serviços Nmap precisam de validação no Kali com ambiente autorizado.

Instalações clonadas pelo Git, sem alterações locais e com atualização automática habilitada podem receber esta versão pelo atualizador. Consulte o README para instalação e uso.
