# CyberOps v1.2.1

A tela JS & Segredos agora mostra onde cada candidato foi encontrado. Antes, a interface descartava a coluna de localização, deixando apenas o tipo e o valor mascarado.

- Arquivo coletado e linha exibidos também para auditorias anteriores.
- Coluna e URL de origem adicionadas em novas auditorias, para localizar trechos em JavaScript minificado.
- Orientação no painel para corrigir a origem no site, revisar falsos positivos e substituir credenciais realmente expostas.
- Valores permanecem mascarados no painel e no relatório.

Selecione o candidato em JS & Segredos. Execute novamente a fase 6 para obter coluna e URL nos resultados antigos. Atualize com `cyberops --atualizar`; instalações v1.2.0 também verificam a release ao abrir.
