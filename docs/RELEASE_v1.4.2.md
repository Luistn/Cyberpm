# Cyberpm v1.4.2

- Abertura com a arte ASCII e um botão **Iniciar**, sem a frase abaixo da imagem.
- O botão Iniciar abre a tela principal no layout de duas colunas, com o campo de site/domínio, ações, autenticação, fases e logs.
- Removidas as telas extras e o formulário de importação manual de APIs. A tela principal usa o layout anterior de duas colunas.
- A fase 7 descobre e testa APIs automaticamente em todos os modos, usando o site, documentos OpenAPI/Swagger descobertos e endpoints dos JavaScripts. Não é necessário importar arquivo.
- Botões com cores explícitas para os estados normal, ativo, pressionado e desabilitado, corrigindo o contraste.
- Mantidos o ASCII no Telegram, os comandos Cyberpm e a correção de atualização anterior.

Validação: 55 testes Python; fluxo de abertura para o campo de site e retorno ao ASCII; geometria dos controles em 1000×650, 1120×720 e 1366×768.

Para atualizar:

```bash
~/.local/bin/cyberpm --atualizar
~/.local/bin/cyberpm open
```
