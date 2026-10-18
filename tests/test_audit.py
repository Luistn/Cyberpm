import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import build_opener

from audit_helpers import api_kind, arjun_urls, normalize, target_host, openapi_get_urls
from api_probe import NoRedirect, auth_headers, probe, summarize
from login_checks import check_login, classify
from port_review import command, inventory
from sensitive_audit import inspect_text, valid_cpf
from cleanup_results import result_directory


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302); self.send_header('Location', 'https://example.invalid'); self.end_headers()
        elif self.path == '/form':
            self.send_response(200); self.send_header('Set-Cookie', 'session=fixture; Path=/'); self.end_headers()
            self.wfile.write(b'<input type="hidden" name="csrf" value="fixture-token">')
        else:
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
            self.wfile.write(b'{"items": [], "private": "never-in-document"}')

    def do_OPTIONS(self):
        self.send_response(204); self.send_header('Allow', 'GET, OPTIONS'); self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/form':
            from urllib.parse import parse_qs
            data = parse_qs(body.decode())
            good = (data.get('csrf') == ['fixture-token'] and self.headers.get('Cookie') == 'session=fixture'
                    and data.get('email') == ['test'] and data.get('password') == ['correct'])
        else:
            data = json.loads(body)
            good = data.get('username') == 'test' and data.get('pass') == 'correct'
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{"access_token":"fixture-secret"}' if good else b'{"success":false,"error":"invalid"}')


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def test_url_scope_and_resolution(self):
        self.assertEqual(normalize('https://example.org', ['/api/a#x', '//evil.invalid/api',
                        'https://user:secret@example.org/api', 'javascript:alert(1)',
                        'https://example.org:8080/a', '/api/a']), ['https://example.org/api/a'])

    def test_sensitive_values_are_visible(self):
        value='fixture-password-123'
        rows=inspect_text('email: test@example.invalid\npassword="'+value+'"', 'fixture.js', b'fixture-salt')
        self.assertEqual(len(rows),2)
        self.assertIn(value,json.dumps(rows))
        self.assertEqual(rows[0]['value'],'test@example.invalid')
        self.assertEqual(rows[1]['line'],2)
        self.assertTrue(valid_cpf('529.982.247-25'))
        self.assertFalse(valid_cpf('111.111.111-11'))

    def test_email_inside_password_is_visible(self):
        rows=inspect_text('password="secret@example.invalid"', 'fixture.js', b'fixture-salt')
        self.assertIn('secret@example.invalid',json.dumps(rows))

    def test_api_fallback_and_arbitrary_json_rejected(self):
        for body in ('<html>SPA</html>', '{"error":"not found"}', '[]'):
            self.assertIsNone(api_kind(body))
        self.assertEqual(api_kind('{"openapi":"3.0.1","info":{},"paths":{}}'), 'OpenAPI')

    def test_arjun_scope_method_and_encoding(self):
        data = {'https://example.org/api': {'method': 'GET', 'params': ['a b', 'id']},
                'https://evil.invalid/api': {'method': 'GET', 'params': ['id']},
                'https://example.org/post': {'method': 'POST', 'params': ['id']}}
        self.assertEqual(arjun_urls('https://example.org', data),
                         ['https://example.org/api?a+b=1', 'https://example.org/api?id=1'])

    def test_target_validation(self):
        self.assertEqual(target_host('https://example.org:443/path'), 'example.org')
        for target in ('https://user:secret@example.org', 'https://-host', 'file:///etc/passwd', 'https://host:99999'):
            with self.assertRaises(ValueError): target_host(target)

    def test_schema_get_routes_scope_and_required_parameters(self):
        schema={'servers':[{'url':'/api/v1'}], 'paths':{
            '/health':{'get':{}}, '/users/{id}':{'get':{}}, '/write':{'post':{}},
            '/search':{'get':{'parameters':[{'name':'q','required':True}]}}}}
        self.assertEqual(openapi_get_urls('https://example.org',schema),['https://example.org/api/v1/health'])
        schema['servers']=[{'url':'https://evil.invalid/api'}]
        self.assertEqual(openapi_get_urls('https://example.org',schema),[])

    def test_api_real_get_metadata_without_values(self):
        result = probe(build_opener(NoRedirect()), self.base+'/api', 'GET', {}, 2)
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['structure'], 'JSON objeto: 2 campos (valores omitidos)')
        self.assertNotIn('never-in-document', json.dumps(result))

    def test_api_options_and_redirect(self):
        result = probe(build_opener(NoRedirect()), self.base+'/api', 'OPTIONS', {}, 2)
        self.assertEqual(result['allow'], 'GET, OPTIONS')
        result = probe(build_opener(NoRedirect()), self.base+'/redirect', 'GET', {}, 2)
        self.assertEqual(result['status'], 302)

    def test_auth_headers(self):
        self.assertEqual(auth_headers({'AUTH_MODE':'bearer','AUTH_SECRET':'fixture'})['Authorization'], 'Bearer fixture')
        self.assertEqual(auth_headers({'AUTH_MODE':'basic','AUTH_USER':'u','AUTH_PASS':'p'})['Authorization'], 'Basic dTpw')

    def test_login_json_custom_fields_correct_and_wrong(self):
        result = check_login(self.base+'/login', 'test', 'correct', user_field='username', password_field='pass')
        self.assertEqual(result['result'], 'sucesso indicado')
        self.assertNotIn('fixture-secret', json.dumps(result))
        result = check_login(self.base+'/login', 'test', 'wrong', user_field='username', password_field='pass')
        self.assertEqual(result['result'], 'recusado')

    def test_login_form_preserves_csrf_and_cookie(self):
        result = check_login(self.base+'/form', 'test', 'correct', fmt='form', csrf_field='csrf')
        self.assertEqual(result['result'], 'sucesso indicado')

    def test_login_missing_csrf_diagnostic(self):
        result = check_login(self.base+'/form', 'test', 'correct', fmt='form', csrf_field='missing')
        self.assertEqual(result['result'], 'revisar configuração')

    def test_login_status_does_not_imply_success(self):
        self.assertEqual(classify(200, '<html>login</html>')[0], 'inconclusivo')
        self.assertEqual(classify(302, '')[0], 'inconclusivo')
        self.assertEqual(classify(429, '')[0], 'bloqueado')
        self.assertEqual(classify(200, 'Dashboard', 'Dashboard')[0], 'sucesso indicado')

    def test_ports_saved_inventory_and_command(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path=Path(directory)/'portas.json'
            path.write_text(json.dumps({'host':'example.org','ports':[{'port':443},{'port':22},{'port':0},{'port':443}]}))
            host, ports=inventory(path)
            self.assertEqual(ports, [22,443])
            args=command(host,ports,path.parent)
            self.assertEqual(args[args.index('-p')+1], '22,443')
            self.assertEqual(args[-1], 'example.org')
            path.write_text(json.dumps({'host':'-iR','ports':[]}))
            with self.assertRaises(ValueError): inventory(path)

    def test_mail_capabilities_and_ipv6(self):
        args = command('::1', [25, 110, 143, 465, 587, 993, 995], Path('.'))
        scripts = args[args.index('--script') + 1].split(',')
        for script in ('smtp-commands', 'imap-capabilities', 'pop3-capabilities'):
            self.assertIn(script, scripts)
        self.assertIn('-6', args)
        self.assertNotIn('smtp-commands', command('localhost', [443], Path('.'))[command('localhost', [443], Path('.')).index('--script') + 1])

    def test_inventory_bom_and_malformed_rows(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / 'ports.json'
            path.write_text(json.dumps({'host': 'localhost', 'ports': [None, 25, {'port': 587}]}), encoding='utf-8-sig')
            self.assertEqual(inventory(path), ('localhost', [587]))
            path.write_text('{"host":"localhost","ports":null}', encoding='utf-8')
            with self.assertRaises(ValueError):
                inventory(path)

    def test_cleanup_rejects_root_and_external_paths(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root=Path(directory)/'cyberpm-out'; root.mkdir()
            site=root/'example.invalid'; site.mkdir()
            self.assertEqual(result_directory(root,site),site.resolve())
            for candidate in (root,Path(directory),root/'missing'):
                with self.assertRaises(ValueError): result_directory(root,candidate)


if __name__ == '__main__':
    unittest.main()
