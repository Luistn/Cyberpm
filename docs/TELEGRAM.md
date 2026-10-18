# Tutorial: configurar Telegram no Cyberpm

![Área real do Telegram na interface](images/telegram-real.png)

## 1. Criar o bot

Abra o aplicativo Telegram e pesquise **@BotFather** (verifique o nome correto). Envie `/start`, depois `/newbot`. Escolha um nome de exibição e um nome de usuário terminado em `bot`. Copie o token recebido e guarde-o em local seguro.

## 2. Iniciar a conversa

Pesquise o nome de usuário do bot que você criou, abra a conversa e envie `/start` e uma mensagem como `teste`.

## 3. Descobrir o Chat ID

No navegador, abra `https://api.telegram.org/botSEU_TOKEN/getUpdates`, substituindo o token apenas no seu computador. Na resposta JSON, encontre `result` → `message` → `chat` → `id`. Esse número é o **Chat ID**. Se `result` estiver vazio, envie outra mensagem ao bot e atualize a página. Em grupos, o ID pode ser negativo e o bot precisa estar adicionado ao grupo.

**Segurança:** não publique o URL completo, pois ele contém o token. Se ele vazar, use o BotFather para revogá-lo e gerar outro.

## 4. Configurar na interface

Execute `cyberpm open`. Role a coluna esquerda até **TELEGRAM**, marque **Enviar notificações**, cole o **Token** e o **Chat ID**, clique em **Salvar** e depois **Testar**. Uma mensagem de teste deverá aparecer no chat.

## 5. Receber relatórios

Ao finalizar ou clicar em **Parar**, a interface gera um relatório HTML com os dados já coletados e tenta enviá-lo pelo bot. O Telegram pode falhar se o bot não tiver permissão, o token estiver incorreto ou não houver internet; confira o log da aplicação.

## Privacidade

Use preferencialmente um chat privado. O token é armazenado localmente em `~/.config/cyberpm/telegram.json`, não dentro do repositório. Não compartilhe capturas de tela contendo o token ou dados sensíveis de auditorias.
