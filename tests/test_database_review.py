import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from database_review import check_tcp, check_sqlite


class DatabaseReviewTests(unittest.TestCase):
    def test_network_results_and_evidence(self):
        for error, status in ((socket.gaierror(), 'dns_error'),
                              (TimeoutError(), 'timeout'),
                              (ConnectionRefusedError(), 'connection_refused')):
            with patch('database_review.socket.create_connection', side_effect=error):
                result = check_tcp('localhost', 'postgresql')
            self.assertEqual(result['status'], status)
            for key in ('where', 'method', 'evidence', 'reproduce', 'remediation', 'exploitation'):
                self.assertIn(key, result)

    def test_all_engines_and_custom_port(self):
        for engine in ('mysql', 'postgresql', 'sqlserver', 'mongodb'):
            with patch('database_review.socket.create_connection', return_value=MagicMock()) as connect:
                result = check_tcp('localhost', engine, 12345)
                connect.assert_called_once_with(('localhost', 12345), timeout=3)
            self.assertEqual(result['status'], 'tcp_accessible')
            self.assertIn('não confirmada', result['classification'])

    def test_sqlite_readonly_and_invalid_file(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / 'fixture.db'
            connection = sqlite3.connect(path)
            connection.execute('CREATE TABLE private_data (secret TEXT)')
            connection.commit()
            connection.close()
            before = path.read_bytes()
            self.assertEqual(check_sqlite(path)['status'], 'ok')
            self.assertEqual(path.read_bytes(), before)
            path.write_bytes(b'not a database')
            self.assertEqual(check_sqlite(path)['status'], 'sqlite_error')
            with self.assertRaises(FileNotFoundError):
                check_sqlite(Path(directory) / 'missing.db')
            self.assertFalse((Path(directory) / 'missing.db').exists())
