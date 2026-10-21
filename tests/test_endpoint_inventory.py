import unittest
import csv
import tempfile
from pathlib import Path
from unittest.mock import patch

from endpoint_inventory import Forms, javascript, main, schema_operations


class EndpointInventoryTests(unittest.TestCase):
    base = 'https://example.invalid/login.php'

    def test_http_clients_and_quote_styles(self):
        text = '''fetch('lookup.php');
        fetch("/orders", {method: 'POST', body: payload});
        axios.patch(`/records/fixture`, {});
        $.get('api/items');
        xhr.open('DELETE', '/records/fixture');'''
        rows = javascript(self.base, text)
        for path, method in (('/lookup.php', 'GET'), ('/orders', 'POST'),
                             ('/records/fixture', 'PATCH'), ('/api/items', 'GET'),
                             ('/records/fixture', 'DELETE')):
            self.assertIn(('https://example.invalid' + path, method), rows)

    def test_scope_and_dynamic_expressions(self):
        self.assertEqual(javascript(self.base, '''fetch('https://other.invalid/api');
            fetch(`/api/${id}`);'''), [])

    def test_nested_payload_and_client_config(self):
        rows = javascript(self.base, '''fetch('/save', {method:'POST', body:{name:'fixture'}});
            axios({url:'/change', method:'PUT', data:{name:'fixture'}});
            $.ajax({url:'remove.php', type:'DELETE'});''')
        self.assertIn(('https://example.invalid/save', 'POST'), rows)
        self.assertIn(('https://example.invalid/change', 'PUT'), rows)
        self.assertIn(('https://example.invalid/remove.php', 'DELETE'), rows)

    def test_method_does_not_leak_between_calls(self):
        rows = javascript(self.base, "fetch('/one'); fetch('/two', {method: 'DELETE'});")
        self.assertIn(('https://example.invalid/one', 'GET'), rows)
        self.assertNotIn(('https://example.invalid/one', 'DELETE'), rows)

    def test_forms_resolve_against_page(self):
        parser = Forms(self.base)
        parser.feed('<form action="save.php" method="post"></form><form action="/search"></form>')
        self.assertEqual(parser.rows, {('https://example.invalid/save.php', 'POST'),
                                       ('https://example.invalid/search', 'GET')})

    def test_openapi_preserves_all_methods_and_path_parameters(self):
        schema = {'servers': [{'url': '/api'}], 'paths': {
            '/items': {'get': {}, 'post': {}},
            '/items/{id}': {'put': {}, 'patch': {}, 'delete': {}}}}
        rows = schema_operations(self.base, schema)
        self.assertEqual({method for _, method in rows}, {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'})
        self.assertIn(('https://example.invalid/api/items/{id}', 'DELETE'), rows)
        schema['servers'] = [{'url': 'https://other.invalid'}]
        self.assertEqual(schema_operations(self.base, schema), [])

    def test_pipeline_keeps_post_in_inventory_without_getting_it(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            out = Path(directory)
            (out / '29_js/arquivos').mkdir(parents=True)
            (out / '08_codigo').mkdir()
            (out / '29_js/manifest.tsv').write_text('https://example.invalid/static/app.js\tapp.js\n')
            (out / '29_js/arquivos/app.js').write_text("axios.post('/save', {}); fetch('lookup.php');")
            (out / '08_codigo/index.html').write_text('<form action="/create" method="post"></form>')
            with patch('sys.argv', ['endpoint_inventory.py', '--base', self.base, '--out', str(out)]):
                main()
            with (out / '06_api/operacoes.tsv').open(encoding='utf-8') as stream:
                rows = list(csv.DictReader(stream, delimiter='\t'))
            self.assertIn({'Endpoint': 'https://example.invalid/create', 'Arquivo': self.base, 'Metodo': 'POST'}, rows)
            self.assertEqual((out / '06_api/endpoints_get.txt').read_text(), 'https://example.invalid/lookup.php\n')
