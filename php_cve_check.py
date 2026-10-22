"""Independent, non-exploit HTTP triage for the October 2026 PHP advisories."""
import re
import urllib.request
import urllib.error
from urllib.parse import urlsplit

SOURCE = 'https://www.php.net/archive/2026.php#2026-10-21-1'
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
LIMITATION = ('Cabeçalhos podem ser ocultados ou alterados. Backports do fornecedor '
              'precisam de confirmação no servidor. Esta triagem não confirma exploração.')


def normalize_target(value):
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    parsed = urlsplit(value)
    if (parsed.scheme not in ('https', 'http') or not parsed.hostname
            or parsed.username or parsed.password or any(c.isspace() for c in value)):
        raise ValueError('Informe uma URL HTTP/HTTPS sem credenciais.')
    parsed.port
    return parsed._replace(fragment='').geturl()


def assess_version(version):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', version)
    if not match:
        return 'INCONCLUSIVO', 'Versão ausente, incompleta ou não estável.'
    major, minor, patch = map(int, match.groups())
    fixed = FIXED.get((major, minor))
    if fixed is None:
        return 'INCONCLUSIVO', 'Ramo fora da matriz de correções; conferir suporte e pacote com o fornecedor.'
    if patch < fixed:
        return 'POTENCIALMENTE AFETADO', f'Versão anterior a {major}.{minor}.{fixed}; atualizar ou comprovar backport.'
    return 'CORREÇÃO INDICADA PELA VERSÃO', f'Versão igual ou posterior a {major}.{minor}.{fixed} neste ramo.'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_url(value, timeout=10):
    url = normalize_target(value)
    result = dict(url=url, status='INCONCLUSIVO', version='', http_status=None,
                  detail='', source=SOURCE, limitation=LIMITATION)
    request = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Cyberpm-PHP-CVE-Triage/1.0'})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            result['http_status'] = response.code
            # Record only relevant software headers; never store cookies or bodies.
            evidence = ' | '.join(response.headers.get_all('X-Powered-By', []) + response.headers.get_all('Server', []))
            result['software_headers'] = evidence
            versions = set(re.findall(r'PHP/([0-9]+\.[0-9]+\.[0-9]+[^\s;,)]*)', evidence, re.I))
            if len(versions) == 1:
                result['version'] = versions.pop()
                result['status'], result['detail'] = assess_version(result['version'])
            else:
                result['detail'] = 'Versão PHP não identificada de forma única; conferir a versão do PHP que atende esta URL no servidor.'
            if 300 <= response.code < 400:
                result['detail'] += ' Redirecionamento não seguido; inclua a URL final explicitamente.'
    except (OSError, ValueError, urllib.error.URLError) as exc:
        result['detail'] = f'Falha de coleta: {exc}'
    return result
