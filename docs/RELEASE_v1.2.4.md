## CyberOps v1.2.4

Corrige a apresentação de portas da última análise restauradas ao abrir o programa: o botão agora identifica o domínio/host e a data do arquivo salvo, mesmo quando o campo Alvo está vazio.

A janela também mostra a origem da evidência e explica que abrir o resultado não executa uma nova varredura. Se portas.txt estiver ausente, as portas do inventário JSON continuam visíveis.

Validação: 7 testes de release e relatório aprovados, incluindo regressão de identificação do host salvo e limpeza do rótulo sem inventário. A data exibida é a modificação do arquivo, não uma garantia do horário da varredura.
