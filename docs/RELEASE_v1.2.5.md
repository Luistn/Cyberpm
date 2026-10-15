## CyberOps v1.2.5

O programa inicia sem carregar automaticamente os resultados do último teste. A tela Achados deixa de selecionar a pasta mais recente, e JS & Segredos limpa lista, detalhes e referências quando não há análise atual. Os arquivos de evidência permanecem no disco.

- Botão Achados no topo direito, ao lado do contador.
- Avisos visuais e sonoros ao encerrar a execução ou o teste de senhas. Conclusão, interrupção e erro recebem mensagens diferentes; o som depende das configurações do sistema.
- Resumo da revisão de portas no próprio log, salvo em 02_portas/port_summary.txt e incluído no HTML. Explica observações, método, evidência, reprodução, correção e limites: identificar um proxy Cloudflare ou uma porta aberta não comprova exploração.
- XML ausente ou incompleto produz avaliação inconclusiva, e execuções parciais recebem indicação explícita.

Validação: suíte Python e verificações Bash locais. Testes usam dados fictícios, servidor HTTP local e simulações; não foram realizados novos testes contra alvos externos.
