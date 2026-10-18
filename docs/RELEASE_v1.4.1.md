# Cyberpm v1.4.1

Corrige o reinício na atualização de versões anteriores à renomeação. O atualizador antigo tentava abrir `cyberops` depois de instalar Cyberpm, causando erro de arquivo inexistente. Uma ponte interna encaminha esse reinício para `cyberpm`, preservando os argumentos. O instalador continua expondo somente o comando `cyberpm`.

Se você já atualizou para v1.4.0 e recebeu o erro, execute:

```bash
hash -r
~/.local/bin/cyberpm open
```

Depois, atualize para a correção:

```bash
~/.local/bin/cyberpm --atualizar
```

Validação: regressões de reinício legado, preservação de argumentos e saída da versão pelo caminho antigo, além da suíte Python completa. Nenhum teste foi executado em alvo externo.
