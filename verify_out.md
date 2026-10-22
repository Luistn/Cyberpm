# Relatorio Cyberpm Precision Pack
Alvo: https://exemplo.com/?id=1

| Severidade | Qtd |
|---|---|
| info | 3 |

## [INFO] CORS mal configurado — inconclusivo (0%)
- **URL:** https://exemplo.com/?id=1
- **Parametro:** id
- **Payload:** -
- **CWE / OWASP:** CWE-942 / A05:2021

- **Reproduzir:** `curl -sk -D - -o /dev/null 'https://exemplo.com/?id=1'`
- **Evidencia:** `{"erro": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1082)>"}`

## [INFO] Cabecalhos de seguranca — inconclusivo (0%)
- **URL:** https://exemplo.com/?id=1
- **Parametro:** id
- **Payload:** -
- **CWE / OWASP:** CWE-693 / A05:2021

- **Reproduzir:** `curl -sk -D - -o /dev/null 'https://exemplo.com/?id=1'`
- **Evidencia:** `{"erro": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1082)>"}`

## [INFO] Cross-Site Scripting — inconclusivo (0%)
- **URL:** https://exemplo.com/?id=1
- **Parametro:** id
- **Payload:** -
- **CWE / OWASP:** CWE-79 / A03:2021

- **Reproduzir:** `curl -sk -D - -o /dev/null 'https://exemplo.com/?id=1'`
- **Evidencia:** `{"erro": "URLError: <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1082)>"}`
