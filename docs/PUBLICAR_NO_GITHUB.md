# Publicar atualizações do Cyberpm

Repositório oficial: https://github.com/Luistn/Cyberpm. O comando instalado consulta as releases desse repositório ao abrir.

## Versão do programa e compatibilidade

A versão exibida é **1.5**. A tag técnica desta distribuição é **v1.7.3**. O atualizador lê a tag técnica; a versão exibida pode seguir uma numeração independente. Alterações locais e arquivos não rastreados são guardados em um stash Git antes da instalação automática; o atualizador não os reaplica sobre a versão nova.

- `VERSION`: versão técnica, `1.7.3`.
- `version_info.json`: associa a release `1.7.3` à versão exibida `1.5`.
- A tag deve corresponder exatamente ao conteúdo de `VERSION`, com prefixo `v`.
- Se `VERSION` mudar sem atualizar essa associação, a interface volta a mostrar a versão técnica, evitando um rótulo antigo.

## Preparar uma publicação

1. Faça as alterações e execute os testes de atualização, da interface e dos componentes afetados.
2. Atualize `VERSION`, `version_info.json`, `CHANGELOG.md`, `README.md` e as notas em `docs/releases/`.
3. Confira `git status` e `git diff`. Prepare apenas os arquivos do programa e da documentação; deixe relatórios e configurações pessoais locais.
4. Crie o commit e envie para `main`, preservando o histórico existente.
5. Crie uma release publicada, sem marcar como prerelease, com a tag técnica do mesmo commit. Marque essa release como a mais recente.
6. Verifique que a API de releases e a página `/releases/latest` indicam a tag publicada.

O atualizador depende da release publicada, não apenas do commit enviado. Não mova tags já publicadas para outro commit.

## Validar a atualização no Kali

Em uma instalação anterior clonada do repositório oficial:

```bash
cyberpm
```

O programa deve consultar a release oficial, baixar a tag, aplicar fast-forward, executar o instalador e reiniciar. Na transição v1.6.4 → v1.6.6 não é necessário executar `git pull` manualmente. A consulta tenta a API e, se ela falhar, usa a página oficial da release.

Confira a versão instalada:

```bash
cyberpm --versao
```

Resultado esperado nesta distribuição: `Cyberpm 1.5 (release 1.7.3)`.

A atualização exige Git, branch `main`, origem oficial, acesso ao GitHub e ausência de alterações locais nos arquivos do programa. Instalações por ZIP exigem atualização manual. Alterações locais e histórico divergente devem ser resolvidos pelo usuário; o atualizador não descarta arquivos nem faz reset.

## Instalação nova

```bash
git clone https://github.com/Luistn/Cyberpm.git
cd Cyberpm
bash instalar.sh
cyberpm
```

Mantenha `update_config.json` apontando para `Luistn/Cyberpm` e `auto_update` como `true`. A configuração de outro repositório não é aceita pelo atualizador oficial.
