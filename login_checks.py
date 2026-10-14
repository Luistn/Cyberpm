"""Session-aware checks for one authorized test account, without guessing formats."""
import json
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener


class ScopedRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        first, second = urlsplit(req.full_url), urlsplit(newurl)
        if (first.hostname != second.hostname or first.port != second.port
                or second.scheme not in ('http', 'https') or second.username or second.password
                or (first.scheme == 'https' and second.scheme != 'https')):
            raise ValueError('redirecionamento fora do escopo')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HiddenFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('type', '').lower() == 'hidden' and attrs.get('name'):
            self.fields[attrs['name']] = attrs.get('value', '')


def classify(status, body, marker=''):
    if status in (423, 429):
        return 'bloqueado', 'bloqueio ou limite de tentativas; execução interrompida'
    if status in (401, 403):
        return 'recusado', 'credenciais recusadas, CSRF ou política de acesso'
    if status in (400, 404, 405, 415, 422):
        return 'revisar configuração', 'verifique URL, campos, formato e requisitos da API'
    if status is None or status >= 500:
        return 'erro', 'conexão/TLS indisponível ou erro do servidor'
    if not 200 <= status < 300:
        return 'inconclusivo', 'HTTP isolado não confirma login'
    if marker and marker in body:
        return 'sucesso indicado', 'marcador configurado encontrado'
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        if data.get('error') or data.get('errors') or data.get('success') is False:
            return 'recusado', 'resposta JSON indica falha'
        candidates = [data] + [data[key] for key in ('data', 'result', 'session') if isinstance(data.get(key), dict)]
        for candidate in candidates:
            if any(isinstance(candidate.get(key), str) and candidate[key]
                   for key in ('access_token', 'accessToken', 'idToken', 'token', 'jwt')):
                return 'sucesso indicado', 'token recebido (valor omitido)'
            if candidate.get('authenticated') is True:
                return 'sucesso indicado', 'API indicou sessão autenticada'
    return 'inconclusivo', 'sem evidência explícita; configure um marcador de sucesso'


def check_login(url, username, password, user_field='email', password_field='password',
                fmt='json', marker='', csrf_field='', extra=None):
    opener = build_opener(ScopedRedirect(), HTTPCookieProcessor(CookieJar()))
    headers = {'User-Agent': 'CyberOps-login-check'}
    payload = dict(extra or {})
    try:
        # Obtain fresh hidden fields and cookies for this attempt only.
        if fmt == 'form' or csrf_field:
            try:
                response = opener.open(Request(url, headers=headers), timeout=6)
            except HTTPError as exc:
                response = exc
            with response:
                if response.code in (423, 429):
                    return {'status': response.code, 'result': 'bloqueado', 'detail': 'bloqueio no formulário inicial'}
                parser = HiddenFields()
                parser.feed(response.read(131072).decode('utf-8', errors='replace'))
            if fmt == 'form':
                payload.update(parser.fields)
            if csrf_field:
                if csrf_field not in parser.fields:
                    return {'status': None, 'result': 'revisar configuração', 'detail': 'campo CSRF configurado não encontrado'}
                payload[csrf_field] = parser.fields[csrf_field]
        payload.update({user_field: username, password_field: password})
        if fmt == 'json':
            body = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        else:
            body = urlencode(payload).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        origin = urlsplit(url)
        headers['Origin'] = origin.scheme + '://' + origin.netloc
        headers['Referer'] = url
        try:
            response = opener.open(Request(url, data=body, headers=headers, method='POST'), timeout=8)
        except HTTPError as exc:
            response = exc
        with response:
            status = response.code
            content = response.read(131073)
        if len(content) > 131072:
            return {'status': status, 'result': 'inconclusivo', 'detail': 'resposta maior que o limite de análise'}
        result, detail = classify(status, content.decode('utf-8', errors='replace'), marker)
        return {'status': status, 'result': result, 'detail': detail}
    except (URLError, TimeoutError, OSError, ValueError):
        return {'status': None, 'result': 'erro', 'detail': 'falha de conexão, TLS ou redirecionamento fora do escopo'}
