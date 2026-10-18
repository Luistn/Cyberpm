<p align="center">
  <img src="docs/images/banner.svg" alt="OP Cybernetica I" width="100%">
</p>

# CyberOps — v1.2.7

**Ferramenta de apoio à auditoria de segurança de aplicações web para Kali Linux**, com interface gráfica, execução pelo terminal, reconhecimento de domínios, inventário técnico, acompanhamento das fases, relatórios HTML e integração opcional com Telegram.

**Repositório oficial:** https://github.com/Luistn/Pentest-cyberops  
**Versão:** v1.2.7

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
- **Terminal ou CyberOps:** execução por comandos `cyberops` ou pela interface gráfica.

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
- **Portas:** a fase 2 salva `02_portas/portas.json`. O botão “Portas descobertas” na coluna esquerda permite escolher portas após a execução. A revisão coleta serviços, banners, cabeçalhos HTTP, certificados e chaves públicas SSH; o resultado fica em `02_portas/port_review.txt` e atualiza o relatório. Ao reabrir o programa, os resultados anteriores não são carregados automaticamente; as evidências permanecem na pasta de resultados.
- **Login:** use a URL real da requisição de autenticação, não apenas a página visual. Configure formato `json` ou `form`, nomes dos campos (ex.: `email`/`password` ou `username`/`pass`), campos extras em JSON e, se necessário, campo CSRF. Formulários reaproveitam cookies e campos ocultos. Para HTML, configure um texto exclusivo da página autenticada em “Marcador de sucesso”. HTTP 200/302 sozinho não confirma login. Há limite de 50 senhas para uma conta, intervalo de um segundo e parada em sucesso indicado, bloqueio ou erro de configuração. Wordlists são limitadas a 50 senhas, lendo no máximo 500 linhas; senhas não entram nos logs. CAPTCHA, MFA e formulários dependentes de JavaScript precisam do login manual no navegador.
- **Dados sensíveis:** `18_ident/dados_sensiveis_mascarados.tsv` reúne tipos de exposição, arquivo, linha e referência; há também uma versão JSON. Verifica CPF por checksum, e-mails, atribuições de senha/segredo, padrões de chave e JWT. Limita a leitura a 2 MB por arquivo e 2.000 candidatos; valores encontrados são exibidos completos. Isso não confirma vazamento nem coleta bancos de credenciais externos. Arquivos de evidência baixados devem permanecer privados.
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

A revisão de portas consulta capacidades SMTP (25/465/587), IMAP (143/993) e POP3 (110/995) quando essas portas estão no inventário e são selecionadas. Não envia mensagens nem tenta autenticação. Falhas do Nmap aparecem no log da interface e em port_review.stderr. A descoberta Nmap aceita alvos IPv6 literais.

## Diagnóstico reutilizável de bancos

O módulo `database_review.py` verifica conectividade TCP para MySQL, PostgreSQL,
SQL Server e MongoDB. O nome do banco indica o serviço esperado: conexão TCP
não confirma protocolo, versão, TLS, permissões ou vulnerabilidade.
SQLite recebe uma verificação local de integridade em modo somente leitura.
Não há tentativa de senha, exploração ou alteração de dados.

```bash
python3 database_review.py --engine mysql --host 127.0.0.1 --output mysql.json
python3 database_review.py --engine postgresql --host 127.0.0.1
python3 database_review.py --engine sqlserver --host 127.0.0.1
python3 database_review.py --engine mongodb --host 127.0.0.1
python3 database_review.py --engine sqlite --file /caminho/projeto/banco.db
```

Use `--port` para uma porta personalizada e `--timeout` entre 0 e 30 segundos
(exclusive zero). A resolução DNS depende do resolvedor do sistema e pode
ultrapassar o timeout de conexão. SQLite limita trabalho da consulta via progress
handler; esse limite não interrompe uma operação de disco bloqueada pelo sistema.
Códigos de saída: 0 para TCP acessível/integridade básica aprovada, 1 para problema
observado, 2 para configuração/arquivo inválido.

Cada resultado inclui localização, método, evidência, parâmetros de reprodução,
orientação de correção e declaração sobre exploração demonstrada. Nenhum destes
checks confirma exploração. Reexecute com os parâmetros de `reproduce` para
reproduzir a observação. Porta acessível só é problema de exposição quando o acesso
contraria a política do projeto. Erro de conexão não comprova vulnerabilidade.
No CyberOps, a revisão de portas gera `02_portas/database_review.json` para as portas
padrão selecionadas (3306, 5432, 1433, 27017), disponível nas evidências da fase 2.
O comando separado permite diagnosticar serviços em portas personalizadas.


### Teste de senhas: como preencher

![Teste de senhas de uma conta](docs/images/login-real.png)

1. Preencha o Alvo e copie a URL da requisição POST de login na aba Rede/Network do navegador.
2. Informe uma conta de teste e até 50 senhas candidatas, uma por linha. Uma wordlist é um arquivo contendo essas senhas.
3. Copie os nomes dos campos enviados no POST (por exemplo, email/password) e escolha json ou form.
4. Para resposta HTML, informe um texto exclusivo da área autenticada no Marcador de sucesso. Configure CSRF/campos extras conforme o formulário real.
5. Clique em Testar senhas e consulte o log e 20_brute/login_resultados.json. HTTP 200/302 sozinho não confirma autenticação.

O teste é separado da varredura: selecionar a fase 29 não inicia tentativas automaticamente. Há intervalo de um segundo e parada em sucesso indicado, bloqueio ou erro. Pode bloquear a conta. CAPTCHA/MFA exigem login manual. A seção Acesso às páginas protegidas reaproveita uma sessão; ela tem outra finalidade.

### MAC e IP no Kali

Selecione a interface correta antes da operação. Requer iproute2, macchanger e, para DHCP, dhclient (pacote isc-dhcp-client quando disponível na distribuição), além de privilégios via pkexec/sudo. O log mostra código de saída e estados antes/depois. A troca de MAC tenta reativar uma interface originalmente ativa mesmo se houver falha. A renovação DHCP pode manter o mesmo endereço; não garante troca de IP público. As operações podem interromper a conexão e dependem de suporte do adaptador/gerenciador de rede. Foram verificadas com testes simulados; a alteração real ainda precisa ser validada no Kali.


### Novidades da v1.2.5

O programa inicia sem carregar resultados anteriores. Portas, Achados e JS & Segredos não selecionam automaticamente a pasta da última análise; as evidências continuam no disco. Há um botão Achados no topo direito, ao lado do contador, e avisos visuais/sonoros ao encerrar a execução ou o teste de senhas (o som depende das configurações do sistema).

Ao revisar portas, o log mostra um resumo interpretado, também salvo em `02_portas/port_summary.txt` e incluído no HTML. O resumo distingue inventário de vulnerabilidade confirmada e informa método, evidência, reprodução, orientação de correção e limites da coleta. XML ausente ou incompleto gera avaliação inconclusiva.


### Organização das fases

Os IDs públicos 1–29 permanecem estáveis. As funções e pastas internas usam numeração histórica, traduzida por LEGACY_BY_NEW: por exemplo, a fase pública 12 usa phase_16 e 16_privacidade. Essa diferença não muda a ordem de execução.

- 1–4: reconhecimento, portas, tecnologias e coleta de URLs.
- 5–8: código, JS, APIs e parâmetros; JS vem antes da análise de APIs.
- 9–15: exposição, DNS/login, cabeçalhos, métodos, TLS e scanner.
- 16: referências a CVEs após coleta de Nmap, Retire.js, TLS e nuclei.
- 17–19 e 21–26: testes específicos e heurísticas, conforme os recursos instalados.
- 27–29: inventário de identificadores, orientação de validação de contas e indicação do teste manual de senhas.
- 20: revisão básica de autorização executada por último, uma única vez, quando selecionada ou incluída pelas fases 27/28. Não valida automaticamente contas nem permissões entre usuários.

O modo Rápido usa 1,2,3,4,5,6,7,8,9,15; Completo e Profundo compartilham a seleção de fases atual. Uma seleção personalizada no CyberOps substitui a seleção do modo. Selecionar fases isoladas não executa automaticamente todas as dependências: por exemplo, os inventários de parâmetros/redirect/SSRF dependem das URLs da fase 4, takeover depende da fase 1, e SQLi/XSS dependem dos parâmetros da fase 8. Verifique os arquivos e o contexto da execução.

O log registra a ordem planejada. Falhas com código diferente de zero aparecem como Falha/parcial no CyberOps e afetam o resultado final. Conclusão de uma etapa não significa que ela confirmou uma vulnerabilidade ou que todas as ferramentas opcionais foram executadas.

Os valores encontrados pelo inventário ficam visíveis integralmente na coluna Valor, com arquivo, linha e coluna. Isso inclui senhas, tokens, chaves e CPF. Esta mudança vale para novas coletas; relatórios antigos não são reescritos automaticamente. Relatórios HTML e arquivos enviados ao Telegram podem conter esses valores completos. Os nomes dados_sensiveis_mascarados.tsv/json são legados, mantidos por compatibilidade; novas coletas nesses arquivos não mascaram valores.


Na v1.2.7, Iniciar teste fica ao lado e antes de Testar login. Passe o mouse sobre uma fase para consultar as ferramentas previstas; isso não confirma que elas estão instaladas.

## Consulta OSINT

A aba **Consulta OSINT** aceita nome, telefone, e-mail e placa brasileira (padrão antigo ou Mercosul). O contexto opcional permite acrescentar cidade ou empresa à busca.

Clique em **Preparar busca**, selecione Google ou Bing e use **Abrir fonte selecionada**. A consulta é enviada ao provedor somente ao abrir a fonte no navegador. Esta versão prepara buscas públicas; não coleta automaticamente resultados, não consulta bases privadas e não identifica proprietários de veículos. Validação de formato não confirma existência ou titularidade.

Registre a URL e a observação de cada evidência e exporte em JSON para preservar fontes, datas UTC e observações. Evidências ficam na memória até exportação e não são enviadas ao Telegram. Correspondências precisam de revisão manual, especialmente nomes com homônimos.

## Ferramentas OSINT no Kali

Instale os complementos opcionais:

```bash
sudo apt update
sudo apt install dnsutils whois python3-phonenumbers
```

Na aba **Consulta OSINT**, prepare a consulta e clique em **Executar ferramentas Kali**. Para e-mail, o CyberOps executa `dig` (MX, TXT, A, AAAA) e `whois` somente sobre o domínio; isso não confirma a existência da caixa postal. Para telefone, usa `phonenumbers` localmente para formato, país/região, fuso e operadora original quando disponíveis. Sem DDI explícito, assume Brasil. Não informa localização atual nem confirma titularidade ou linha ativa.

A saída aparece na aba e é incluída em `tool_results` na exportação JSON, com comando, horário e situação. Ferramentas ausentes, erros e limites de tempo são registrados. Nome e placa continuam com buscas públicas no navegador, sem adaptador de cadastro pessoal/veicular. Dependências aplicáveis ausentes são instaladas automaticamente ao executar as ferramentas, exceto com “Não instalar ferramentas” marcado. O Kali pode solicitar autenticação pelo sistema; falhas de instalação aparecem no painel. Consultas DNS/WHOIS usam a rede; a análise de telefone usa metadados locais.

## Subdomínios, WordPress e logs

Depois da fase 1, clique em **Subdomínios descobertos**. Selecione um host da lista, marque que ele pertence ao escopo autorizado e clique em **Analisar selecionado**. As fases e o modo atuais serão usados, com saída e relatório por host. A sessão de login anterior é removida ao trocar de host. Analise um subdomínio por vez; a descoberta não confirma que ele está acessível.

Marque **WordPress (WPScan na fase 3)** e inclua a fase 3 para executar inventário de WordPress, plugins e temas com detecção passiva. O WPScan é instalado quando ausente, respeitando “Não instalar ferramentas”. O tempo máximo é de 180 segundos. Consulte `03_tech/wpscan.stdout` e `wpscan.stderr`, também incluídos no relatório. A detecção passiva pode deixar componentes sem identificar; dados de vulnerabilidades dependem de token/API configurados no próprio WPScan. Não são executados testes de senhas pelo WPScan.

Os logs usam roxo para fases, azul para informações, verde para sucesso, amarelo para avisos, vermelho para erros e achados altos/críticos e rosa para outros achados. O texto original é preservado para cópia.

## OSINT independente e junto da auditoria

Use **Consulta OSINT** para consultas avulsas, com identificação automática de nome, `@usuário`, telefone, e-mail, placa ou domínio. O tipo pode ser ajustado manualmente antes de preparar a consulta. As ferramentas só executam pelo botão **Executar ferramentas Kali**.

Ao iniciar uma auditoria de site, o OSINT do domínio começa junto da primeira fase, depois da verificação de dependências do executor. A linha **OSINT — consulta pública** exibe o estado no painel de fases; clique duas vezes para abrir a aba. O log colorido recebe os resultados. OSINT tem acompanhamento próprio e não altera o contador das 29 fases web. Se uma consulta avulsa já estiver em execução, o log informa que o OSINT do site não foi iniciado.

Cobertura integrada:

- **Domínio:** DNS (MX, TXT, A, AAAA, NS, CAA, SOA e DMARC), WHOIS e subdomínios públicos com Subfinder.
- **E-mail:** DNS e WHOIS do domínio, sem confirmar a caixa postal.
- **Usuário:** Sherlock busca perfis públicos por apelido; resultados não confirmam identidade. Use `@apelido` para identificação automática.
- **Telefone:** metadados locais com phonenumbers.
- **Nome e placa:** consultas públicas preparadas para revisão no navegador; sem cadastro privado integrado.

Sherlock e Subfinder são instalados quando necessários no modo avulso, respeitando **Não instalar ferramentas**. Algumas fontes do Subfinder exigem chaves configuradas na própria ferramenta. Consultas anteriores com evidências/resultados ficam no histórico da sessão e acompanham a exportação JSON. A análise de sites preserva esse histórico ao preparar o domínio automaticamente.
