# Cyberpm v1.4.3

- Removido o ASCII da mensagem de início do Telegram. A abertura local continua com a arte e o botão Iniciar.
- Botões menores e mais finos: Iniciar teste, Parar, Fases, Achados, Relatório e Testar login na mesma fileira.
- WPScan ao lado dos controles principais, desmarcado por padrão.
- JS & Segredos e Subdomínios lado a lado; Portas e Limpar resultados lado a lado.
- Mantidos o campo do site, o painel de duas colunas e a revisão automática de APIs.

Validação: 55 testes Python; geometria dos controles em 1000×650, 1120×720 e 1366×768; mensagem de Telegram validada com transporte simulado, sem envio real.

```bash
~/.local/bin/cyberpm --atualizar
~/.local/bin/cyberpm open
```
