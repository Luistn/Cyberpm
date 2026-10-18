# Publicar Cyberpm no GitHub — passo a passo

## A. Criar conta e repositório

1. Entre em https://github.com e faça login (ou crie sua conta).
2. No canto superior direito, clique no símbolo **+** e escolha **New repository**.
3. Em **Repository name**, escreva `Cyberpm`.
4. Marque **Public** para permitir que outras pessoas vejam e baixem o projeto.
5. **Não marque** as opções para criar README, `.gitignore` ou licença: esses arquivos já estão no pacote.
6. Clique em **Create repository**. Deixe essa página aberta.

## B. Preparar os arquivos no Kali

1. Baixe e extraia o ZIP do projeto em uma pasta, por exemplo `~/Cyberpm`.
2. Abra o arquivo `update_config.json` e substitua o campo vazio pelo endereço do seu GitHub:

   ```json
   {"github_repo": "SEU_USUARIO/Cyberpm"}
   ```

   Use o **seu** nome de usuário, sem `https://github.com/`.
3. Confira que `README.md`, `docs/images/interface-real.png`, `docs/images/telegram-real.png`, `cyberpm_gui.py`, `cyberpm.sh`, `cyberpm` e `instalar.sh` estão na pasta.
4. Nunca coloque senhas, tokens do Telegram, dados de clientes ou relatórios no projeto.

## C. Enviar ao GitHub pelo terminal

Abra o terminal **dentro da pasta extraída** e execute, um comando por vez:

```bash
cd ~/Cyberpm
git init
git config user.name "SEU NOME"
git config user.email "SEU_EMAIL_DO_GITHUB"
git add .
git status
git diff --cached --stat
git commit -m "Primeira versão pública Cyberpm v1.0.0"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/Cyberpm.git
git push -u origin main
```

Substitua `SEU_USUARIO`, nome e e-mail pelos seus dados. No `git status`, verifique os arquivos listados. Se aparecer um token, credencial ou relatório privado, **pare antes do commit** e retire o arquivo.

**Autenticação:** o GitHub pode pedir login pelo navegador ou credencial Git. Senha comum da conta não funciona como senha Git via HTTPS; use um método suportado, como Git Credential Manager ou token de acesso pessoal com permissões adequadas. Não coloque tokens nos comandos publicados.

## D. Criar a primeira versão para download (Release)

1. Abra `https://github.com/SEU_USUARIO/Cyberpm`.
2. Na lateral, procure **Releases** e clique em **Create a new release** (ou **Draft a new release**).
3. Clique em **Choose a tag** e digite `v1.0.0`; selecione **Create new tag**.
4. Em **Release title**, escreva `Cyberpm v1.0.0`.
5. Em **Description**, informe que é a primeira versão pública, com interface, CLI, reconhecimento, relatórios e Telegram.
6. Clique em **Publish release**. O GitHub disponibilizará arquivos ZIP e TAR.GZ do código automaticamente.

**Importante:** o verificador de atualização depende das Releases publicadas, não apenas dos commits no repositório.

## E. Testar como um usuário novo

Em outra pasta do Kali:

```bash
cd ~
git clone https://github.com/SEU_USUARIO/Cyberpm.git cyberpm-teste
cd cyberpm-teste
bash instalar.sh
cyberpm --h
cyberpm --versao
cyberpm open
```

Verifique se o README mostra a captura real, se o bot Telegram está documentado e se a interface abre.

## F. Publicar atualizações futuras

1. Faça as alterações e teste localmente.
2. Atualize `VERSION`, o texto da versão na GUI/CLI, `CHANGELOG.md` e documentação quando necessário.
3. Execute `git add .`, `git commit -m "Descrição da atualização"` e `git push`.
4. Em **Releases → Draft a new release**, crie a próxima tag, por exemplo `v1.0.1`, e publique.
5. Quem tiver o programa instalado verá o aviso de versão mais recente ao executar o comando, desde que a configuração do repositório e a internet estejam funcionando.

## G. Alternativa sem terminal

Na página do repositório, **Add file → Upload files** permite enviar arquivos manualmente. É menos prático para manter pastas, atualizações e histórico. Recomendo o método Git do item C.
