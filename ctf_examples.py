"""Disposable files and a loopback HTTP service for classroom examples."""
from contextlib import closing
from html import escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit


class ExampleHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, body, status=200, headers=None):
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-CTF-Example', 'CTF{cabecalho_local}')
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == '/admin':
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            role = cookies.get('papel')
            self.respond('CTF{admin_local}' if role and role.value == 'admin' else 'Acesso restrito',
                         200 if role and role.value == 'admin' else 403)
        elif target.path == '/perfil':
            self.respond('<h1>Conta aluno</h1><a href="/admin">Área administrativa</a>',
                         headers={'Set-Cookie': 'papel=aluno; Path=/; SameSite=Lax'})
        elif target.path == '/busca':
            query = parse_qs(target.query).get('q', [''])[0]
            form = '<form><input name="q"><button>Buscar</button></form>'
            with closing(sqlite3.connect(':memory:')) as connection:
                connection.executescript("CREATE TABLE materiais(nome TEXT); INSERT INTO materiais VALUES('Redes');"
                                         "CREATE TABLE cofre(flag TEXT); INSERT INTO cofre VALUES('CTF{sql_local}');")
                try:
                    # Intentionally vulnerable in this disposable loopback example.
                    rows = connection.execute("SELECT nome FROM materiais WHERE nome = '" + query + "'")
                    self.respond(form + ''.join('<p>' + escape(row[0]) + '</p>' for row in rows))
                except sqlite3.Error as exc:
                    self.respond(form + escape(str(exc)), 400)
        elif target.path == '/xss':
            value = parse_qs(target.query).get('q', [''])[0]
            self.respond('<form><input name="q"><button>Enviar</button></form>'
                         '<p id="prova"></p><script>function provarXSS(){'
                         'document.getElementById("prova").textContent="CTF{xss_local}";}</script>'
                         '<p>Resultado: ' + value + '</p>')
        else:
            self.respond('<h1>Exemplo CTF local</h1><form method="post" action="/login">'
                         '<input name="user"><input name="pass" type="password"><button>Entrar</button></form>'
                         '<a href="/perfil">Perfil</a> · <a href="/busca?q=Redes">Busca</a> · '
                         '<a href="/xss?q=teste">XSS</a>')

    def do_POST(self):
        if self.path != '/login':
            return self.respond('Rota desconhecida', 404)
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.respond('Tamanho inválido', 400)
        if not 0 <= length <= 4096:
            return self.respond('Requisição grande demais', 413)
        values = parse_qs(self.rfile.read(length).decode('utf-8', errors='replace'))
        success = values.get('user') == ['aluno'] and values.get('pass') == ['rede2026']
        self.respond('LOGIN_ACEITO' if success else 'LOGIN_INVALIDO')


class CtfExamples:
    def __init__(self):
        self.directory = None
        self.server = None
        self.thread = None

    def files(self):
        if self.directory is None:
            self.directory = tempfile.TemporaryDirectory(prefix='cyberpm-ctf-', ignore_cleanup_errors=True)
            root = Path(self.directory.name)
            assets = Path(__file__).resolve().parent / 'assets' / 'ctf'
            for name in ('trafego.pcap', 'cartao.png', 'acesso.log', 'resposta.http.txt'):
                shutil.copyfile(assets / name, root / name)
            (root / 'senhas.txt').write_text('aluno123\nlab2025\nrede2026\nsenha000\n', encoding='utf-8')
            (root / 'palavras.txt').write_text('exame123\ncaderno42\nfaculdade\nterminal1\n', encoding='utf-8')
            (root / 'hashes.txt').write_text(
                'aluno:$6$ctflab$ggB5vrEIJOuWkdyFgWr4zFl6G4FxWYKOp.Fxcg7/sOol7DrewitqE0VY/vf3.SA72Jweba0HQV4S3.hyEIpeg0\n',
                encoding='utf-8')
        return Path(self.directory.name)

    def start(self):
        if self.server is None:
            self.server = ThreadingHTTPServer(('127.0.0.1', 0), ExampleHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        return self.server.server_address[1]

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.server = None
            self.thread = None
        if self.directory is not None:
            self.directory.cleanup()
            self.directory = None
