import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from api_probe import main, request_plan


class RequestPlanTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.folder = Path(self.directory.name)
        self.plan = self.folder / 'plan.json'
        self.candidates = self.folder / 'candidates.txt'
        self.candidates.write_text('')
        self.hits = []
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                data = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                hits.append((self.command, self.path, data, self.headers.get('Content-Type')))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{}')

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.base = f'http://127.0.0.1:{self.server.server_port}/login.php'

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def run_plan(self, execute=False, expected_return=0):
        args = ['api_probe.py', '--base', self.base, '--candidates', str(self.candidates),
                '--out', str(self.folder), '--request-plan', str(self.plan)]
        if execute:
            args.append('--execute-plan')
        with patch('sys.argv', args), patch('api_probe.time.sleep'):
            self.assertEqual(main(), expected_return)

    def test_dry_run_sends_nothing(self):
        self.plan.write_text(json.dumps([{'method': 'DELETE', 'url': '/fixture/1'}]))
        self.run_plan()
        self.assertEqual(self.hits, [])
        rows = json.loads((self.folder / 'api_resultados.json').read_text(encoding='utf-8'))
        self.assertIsNone(rows[0]['status'])
        self.assertIn('não executada', rows[0]['assessment'])

    def test_methods_body_and_expected_status(self):
        self.plan.write_text(json.dumps([
            {'method': method, 'url': '/fixture/1', 'json': {'test': True}, 'expected_status': [200]}
            for method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]))
        self.run_plan(execute=True)
        self.assertEqual([hit[0] for hit in self.hits], ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
        self.assertTrue(all(json.loads(hit[2]) == {'test': True} for hit in self.hits))
        self.assertTrue(all(hit[3] == 'application/json' for hit in self.hits))
        rows = json.loads((self.folder / 'api_resultados.json').read_text(encoding='utf-8'))
        self.assertTrue(all(row['validation'] == 'status esperado' for row in rows))

    def test_entire_plan_validated_before_any_request(self):
        for invalid in ({'method': 'DELETE', 'url': 'https://other.invalid/1'},
                        {'method': 'UPDATE', 'url': '/fixture/1'},
                        {'method': 'POST', 'url': '/fixture/1', 'headers': {'Host': 'other.invalid'}},
                        {'method': 'DELETE', 'url': '/fixture/{id}'}):
            with self.subTest(invalid=invalid):
                self.plan.write_text(json.dumps([{'method': 'POST', 'url': '/fixture/1'}, invalid]))
                with self.assertRaises(ValueError):
                    request_plan(self.base, self.plan)
                self.assertEqual(self.hits, [])

    def test_failed_precondition_stops_later_write(self):
        self.plan.write_text(json.dumps([
            {'method': 'GET', 'url': '/fixture/1', 'expected_status': [404]},
            {'method': 'DELETE', 'url': '/fixture/1'}]))
        self.run_plan(execute=True, expected_return=1)
        self.assertEqual([hit[0] for hit in self.hits], ['GET'])
