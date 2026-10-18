## Cyberpm v1.2.6

Melhora o diagnóstico das fases 9, 12, 13, 20 e 23–26: mostra status, evidências, candidatos e limitações, inclusive quando não há resultados ou a consulta falha.

- Ctrl+C em textos/listas e botão Copiar log.
- CVEs listadas por ID único, referência e evidência; citação não comprova aplicabilidade nem exploração.
- Revisão básica de autorização ao final quando selecionada ou incluída pelas fases 27/28. Não valida automaticamente permissões entre contas.
- Modo Rápido respeitado pela GUI; seleção personalizada substitui o modo. Fases com erro aparecem como Falha/parcial e afetam o código final.
- Nomes das fases ajustados ao que realmente executam: inventário/heurística, orientação ou teste manual.
- Valores encontrados no inventário e em JS & Segredos são exibidos completos, incluindo senhas, tokens, chaves e CPF, conforme configuração solicitada. O HTML e o envio ao Telegram também podem incluir esses valores. Arquivos antigos não são reconstruídos; nomes contendo mascarados permanecem apenas por compatibilidade.

Validação com testes Python, sintaxe Bash, regressões HTTP simuladas e cópia de texto na GUI. Nenhum novo teste em alvo externo.
