# Cyberpm v1.2.2

Corrige o erro `TclError: invalid command name` ao concluir uma varredura depois de fechar a janela JS & Segredos. A interface verifica se os widgets ainda existem antes de atualizá-los. Falhas na atualização pós-execução são registradas sem interromper o processamento de eventos.

Validação: teste de regressão para janela fechada, suíte Python e reprodução com widgets Tkinter reais destruídos.

Atualize com `cyberpm --atualizar` e reabra o programa.
