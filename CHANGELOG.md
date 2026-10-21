## v1.6.0

- Adiciona camada de verificacao diferencial (`verify.py`): reexecuta achados com
  controle + payload, confirma em duas rodadas e atribui veredito e confianca.
- Adiciona esquema unico de achados (`findings.py`) com deduplicacao, severidade,
  mapeamento CWE/OWASP/CVSS e exportacao em JSON, TSV, Markdown e SARIF.
- Adiciona inventario e instalacao de ferramentas (`toolkit.py`).
- Adiciona descoberta unificada de ativos (`assets.py`).
- Relatorios agora distinguem achado confirmado de achado inconclusivo.