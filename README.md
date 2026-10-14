<p align="center">
  <img src="docs/images/banner.svg" alt="OP Cybernetica I" width="100%">
</p>

# CyberOps — v1.2.2

**Ferramenta de apoio à auditoria de segurança de aplicações web para Kali Linux**, com interface gráfica, execução pelo terminal, reconhecimento de domínios, inventário técnico, acompanhamento das fases, relatórios HTML e integração opcional com Telegram.

**Repositório oficial:** https://github.com/Luistn/Pentest-cyberops  
**Versão:** v1.2.2

> **Uso autorizado:** execute verificações ativas somente em sistemas próprios ou com autorização expressa. URLs de terceiros identificadas durante a coleta, como CDNs e redes sociais, não passam automaticamente a integrar o escopo autorizado. Um alerta automatizado não comprova, por si só, uma vulnerabilidade.

## Interface do sistema

![Captura real da interface OP Cybernetica I](docs/images/interface-real.png)

*Captura da interface executada em ambiente Linux com servidor gráfico virtual, sem varredura em andamento. A aparência pode variar conforme o ambiente.*

## Para que serve?

O **OP Cybernetica I** reúne em uma interface única recursos de apoio à análise de aplicações web:

- **Reconhecimento de domínio:** consultas públicas WHOIS, RDAP e DNS, incluindo registros e informações cadastrais divulgadas pelos serviços de registro.
- **Inventário técnico:** identificação de serviços, tecnologias, páginas, arquivos JavaScript, endpoints e APIs.
- **Verificações de segurança:** organização de até 29 fases, de acordo com as ferramentas instaladas e a aplicabilidade ao alvo.
- **Acompanhamento:** visualização de progresso, logs e achados durante a execução.
- **Relatórios:** geração de HTML ao concluir ou interromper uma análise, com os resultados disponíveis até aquele momento.
- **Telegram:** notificações e tentativa de envio do relatório para um chat configurado.
- **Terminal ou GUI:** execução por comandos `cyberops` ou pela interface gráfica.

**Limitações:** nem todas as fases se aplicam a todos os sites. Algumas dependem de ferramentas externas não instaladas pelos requisitos básicos. Informações de titulares e contatos podem estar ocultas por privacidade. Resultados precisam ser revisados manualmente.

## Instalação no Kali Linux — passo a passo

### 1. Instale os requisitos básicos

Abra o terminal do Kali e execute os comandos **separadamente**:

```bash
sudo apt update
sudo apt install -y git python3 python3-tk bash curl whois dnsutils
```

### 2. Baixe o projeto oficial

```bash
git clone https://github.com/Luistn/Pentest-cyberops.git
```

### 3. Entre na pasta criada

```bash
cd Pentest-cyberops
```

### 4. Instale o comando `cyberops`

```bash
bash instalar.sh
```

O instalador cria um atalho para o executável em `~/.local/bin/cyberops`. **Mantenha a pasta clonada**, pois o atalho aponta para os arquivos nela.

### 5. Abra um novo terminal e teste

```bash
cyberops --h
cyberops --versao
cyberops open
```

Se aparecer `cyberops: command not found`, adicione `~/.local/bin` ao `PATH`. No Kali, que geralmente usa Zsh:

```bash
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Se estiver usando Bash, substitua `~/.zshrc` por `~/.bashrc`.

### 6. Faça a primeira utilização

Na interface, informe **um alvo autorizado**, escolha o modo e as fases desejadas e inicie a análise. Acompanhe as áreas de **Log**, **Fases**, **Achados** e **Relatório**. Consulte o log se alguma ferramenta externa estiver ausente.

**Alternativa sem Git:** na [página do projeto](https://github.com/Luistn/Pentest-cyberops), clique em **Code → Download ZIP**, extraia o conteúdo, abra o terminal na pasta extraída e execute `bash instalar.sh`.

## Comandos disponíveis

```bash
cyberops                                  # abre a interface gráfica
cyberops open                             # abre a interface gráfica
cyberops --gui                            # abre a interface gráfica
cyberops --h                              # exibe a ajuda
cyberops --versao                         # exibe a versão instalada
cyberops --alvo "https://exemplo.com" --rapido
cyberops --alvo "https://exemplo.com" --completo
cyberops --alvo "https://exemplo.com" --profundo
cyberops --alvo "https://exemplo.com" --fases 1,2,3,6
cyberops --alvo "https://exemplo.com" --completo --obs "Auditoria autorizada"
cyberops --atualizar                      # verifica novas versões
```

Para ambientes de teste com **HTTP Basic**, há suporte a `--usuario conta_teste --pedir-senha`. A senha é solicitada sem ser mostrada no terminal. Isso **não equivale a login automático em formulários web**. Não coloque senhas em `--obs` ou em comandos compartilhados.

## Telegram — configurar notificações e relatórios

A integração é opcional. O tutorial completo está em **[docs/TELEGRAM.md](docs/TELEGRAM.md)**.

1. No Telegram, abra o bot oficial [@BotFather](https://t.me/BotFather) e envie `/newbot`.
2. Escolha o nome e o nome de usuário do bot (terminado em `bot`). Guarde o **token** fornecido; ele é secreto.
3. Abra a conversa com seu novo bot e envie `/start`.
4. Para localizar o **Chat ID**, consulte `https://api.telegram.org/botSEU_TOKEN/getUpdates` em seu navegador, substituindo `SEU_TOKEN` apenas localmente. Procure `message.chat.id`. Se `result` estiver vazio, envie uma mensagem ao bot e consulte novamente.
5. Abra `cyberops open`. Na área **Telegram**, informe **Token** e **Chat ID**, habilite **Enviar notificações**, salve e utilize o teste de envio, se disponível.
6. Ao concluir ou interromper uma análise, o sistema tenta enviar o relatório HTML ao chat configurado. Isso depende da conexão e das permissões do bot.

![Seção Telegram na interface](docs/images/telegram-real.png)

> **Privacidade:** não publique token, Chat ID privado, capturas com credenciais, logs ou relatórios contendo dados sensíveis. A configuração local do Telegram não deve ser enviada ao GitHub.

## Atualizações

As versões oficiais são publicadas em: **https://github.com/Luistn/Pentest-cyberops/releases**.

Ao abrir pelo comando `cyberops`, o programa consulta a última release oficial. **Quando houver uma nova versão, informa, instala automaticamente e reinicia o programa. Isso requer uma instalação clonada pelo Git, na branch main, com origin oficial e sem alterações locais no código. Configurações em ~/.config/pentest-gui e resultados em pentest-out são preservados.** Em instalações anteriores à v1.2.0, a primeira atualização ainda usa a confirmação existente: responda `s` e abra novamente.

Para que a verificação funcione, o arquivo `update_config.json` do projeto deve conter:

```json
{
  "github_repo": "Luistn/Pentest-cyberops",
  "auto_update": true
}
```

**Verificar se existe atualização:**

```bash
cyberops --atualizar
```

**Atualizar uma instalação clonada com Git:**

```bash
cd ~/Pentest-cyberops
git pull --ff-only
bash instalar.sh
```

Se você clonou o projeto em outra pasta, entre nela antes de executar `git pull`. Para quem instalou pelo ZIP, baixe a versão mais recente em [Releases](https://github.com/Luistn/Pentest-cyberops/releases) e siga as instruções da publicação.

## Recursos da v1.2.0

Na v1.2.1, selecione um candidato na tela **JS & Segredos** para ver arquivo coletado, linha, coluna e URL de origem. Auditorias antigas mostram o arquivo e a linha disponíveis; execute novamente a fase 6 para obter coluna/URL. Corrija o código-fonte ou a configuração do site e publique novamente; a cópia em pentest-out é apenas uma evidência local.

- **Instalação no Kali:** ao iniciar a varredura, verifica as ferramentas e tenta instalar as ausentes via apt; Retire.js usa npm com prefixo `~/.local`. O índice apt é atualizado uma vez; gau/waybackurls têm alternativa por Go quando o pacote apt não estiver disponível. Desmarque “Não instalar ferramentas” para habilitar isso. Sem privilégios, execute `sudo -v` no terminal antes de `cyberops open`; em sessão gráfica, pkexec pode solicitar a senha do sistema. Falhas de rede, pacotes indisponíveis e falta de privilégio ficam em `00_dependencias/status.tsv` e `instalacao.log`. Docker/ZAP são integrações opcionais já instaladas e não são provisionadas automaticamente.
- **APIs:** no modo Completo/Profundo, a fase 7 executa GET e OPTIONS em até oito URLs do host, com limite de tamanho/tempo, sem seguir redirecionamentos. Prioriza rotas GET declaradas em OpenAPI que não exigem parâmetros; não inventa IDs ou corpos para POST/PUT/DELETE. Autenticação configurada é reaproveitada. Status, tempo, tipo de conteúdo, estrutura JSON e cabeçalhos CORS ficam em `06_api/api_resultados.tsv` e no relatório HTML. Respostas privadas e tokens não são copiados para esse resumo.
- **Portas:** a fase 2 salva `02_portas/portas.json`. O botão “Portas descobertas” na coluna esquerda permite escolher portas após a execução. A revisão coleta serviços, banners, cabeçalhos HTTP, certificados e chaves públicas SSH; o resultado fica em `02_portas/port_review.txt` e atualiza o relatório. O último diretório é lembrado ao reabrir o programa.
- **Login:** use a URL real da requisição de autenticação, não apenas a página visual. Configure formato `json` ou `form`, nomes dos campos (ex.: `email`/`password` ou `username`/`pass`), campos extras em JSON e, se necessário, campo CSRF. Formulários reaproveitam cookies e campos ocultos. Para HTML, configure um texto exclusivo da página autenticada em “Marcador de sucesso”. HTTP 200/302 sozinho não confirma login. Há limite de 50 senhas para uma conta, intervalo de um segundo e parada em sucesso indicado, bloqueio ou erro de configuração. Wordlists são limitadas a 50 senhas, lendo no máximo 500 linhas; senhas não entram nos logs. CAPTCHA, MFA e formulários dependentes de JavaScript precisam do login manual no navegador.
- **Dados sensíveis:** `18_ident/dados_sensiveis_mascarados.tsv` reúne tipos de exposição, arquivo, linha e referência; há também uma versão JSON. Verifica CPF por checksum, e-mails, atribuições de senha/segredo, padrões de chave e JWT. Limita a leitura a 2 MB por arquivo e 2.000 candidatos; valores permanecem mascarados. Isso não confirma vazamento nem coleta bancos de credenciais externos. Arquivos de evidência baixados devem permanecer privados.
- **Diagnósticos:** `fases_status.tsv` registra duração/código de cada fase; `ferramentas.tsv` registra os comandos limitados. Um timeout pode deixar resultados parciais, que precisam ser revisados. Arjun/testssl/Retire.js são omitidos no modo Rápido.
- **Limpeza local:** o botão “Limpar resultados locais” apaga, após confirmação, apenas a pasta do site selecionado dentro de `pentest-out` e limpa os painéis. Fica bloqueado durante testes. Não apaga configurações, logs do sistema, do servidor, arquivos enviados ao Telegram ou cópias externas.

### Verificação local

```bash
python3 -B -m unittest discover -s tests -v
bash tests/test_shell.sh
```

Os testes usam servidor HTTP local e dados fictícios; não varrem sistemas externos. As integrações apt/npm e as ferramentas reais devem ser verificadas no Kali com um alvo autorizado.

## Documentação

- [Tutorial de configuração do Telegram](docs/TELEGRAM.md)
- [Como capturar imagens reais da interface](docs/CAPTURAS.md)
- [Guia de publicação no GitHub](docs/PUBLICAR_NO_GITHUB.md)
- [Histórico de versões](CHANGELOG.md)
- [Licença MIT](LICENSE)

## Segurança e responsabilidade

Use apenas em ambientes próprios ou expressamente autorizados. Respeite o escopo e os limites de tráfego acordados. Revise manualmente os alertas antes de classificá-los como falhas confirmadas. Antes de enviar alterações ao GitHub, confira `git status` e `git diff --cached` para não publicar credenciais, tokens, cookies, relatórios ou dados privados.
