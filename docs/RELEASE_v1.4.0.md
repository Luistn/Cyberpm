# Cyberpm v1.4.0

## Mudanças

- Sistema, comandos e repositório renomeados para **Cyberpm**: `cyberpm`, `cyberpm.sh` e `cyberpm_gui.py`.
- Removida a aba OSINT e suas consultas pessoais, ferramentas e execução integrada.
- Mantidos reconhecimento técnico de sites, subdomínios, WPScan e revisão das APIs.
- Central de auditoria com etapas agrupadas, consulta a resultados anteriores e validação manual de achados com reprodução, impacto e hash da evidência.
- Importação de contratos OpenAPI/Swagger JSON para revisar rotas GET na mesma origem, com limites de tempo e botão de interrupção.
- Tela inicial com a arte ASCII enviada pelo usuário, banner no terminal e arte monoespaçada na mensagem de início do Telegram.
- Controles reorganizados para melhorar a visibilidade em telas menores.

## Atualizar uma instalação anterior

Entre na pasta já instalada e execute:

```bash
git remote set-url origin https://github.com/Luistn/Cyberpm.git
git pull --ff-only
bash instalar.sh
hash -r
cyberpm open
```

O instalador substitui o atalho antigo dessa instalação. Configurações antigas continuam sendo lidas quando ainda não há configurações no novo diretório. Resultados anteriores permanecem no disco; novas auditorias usam `cyberpm-out`.

## Validação e limites

55 testes Python passaram, além das regressões e sintaxe Bash. Interface conferida em 1000×650, 1120×720 e 1366×768 sem botões cortados horizontalmente. Telegram validado com transporte simulado; nenhuma mensagem real foi enviada nos testes. A instalação de ferramentas e execução real do WPScan no Kali ainda precisam de validação nesse ambiente.

O Cyberpm usa motor determinístico e validação registrada pelo auditor. A organização de evidências e revisão por contrato inspira-se no fluxo do Strix; esta versão não implementa a autonomia de agentes de IA do Strix.
