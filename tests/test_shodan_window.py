import io
import json
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from shodan_window import lookup, search_query


class ShodanTests(unittest.TestCase):
    def test_geographic_filters_are_quoted_and_validated(self):
        self.assertEqual(search_query('hostname:example.org', 'br', 'Sao Paulo', 'Campinas'),
                         'hostname:example.org country:BR state:"Sao Paulo" city:"Campinas"')
        with self.assertRaises(ValueError):
            search_query('', 'Brasil')
        with self.assertRaises(ValueError):
            search_query()

    def test_ip_without_key_uses_internetdb(self):
        with patch('shodan_window.urlopen', return_value=io.BytesIO(b'{"ip":"1.1.1.1","ports":[443]}')) as request:
            self.assertEqual(lookup('IP', '1.1.1.1')['ports'], [443])
        self.assertEqual(request.call_args.args[0].full_url, 'https://internetdb.shodan.io/1.1.1.1')
        with self.assertRaises(ValueError):
            lookup('IP', 'https://example.org/login')

    def test_search_encodes_filters_and_does_not_echo_key(self):
        with patch('shodan_window.urlopen', return_value=io.BytesIO(b'{"total":0,"note":"private-key"}')) as request:
            result = lookup('Pesquisa', 'hostname:example.org', 'private-key', 'BR', 'Sao Paulo')
        params = parse_qs(urlsplit(request.call_args.args[0].full_url).query)
        self.assertIn('state:"Sao Paulo"', params['query'][0])
        self.assertNotIn('private-key', json.dumps(result))
        with self.assertRaises(ValueError):
            lookup('Pesquisa', 'hostname:example.org')

    def test_network_errors_hide_authenticated_url(self):
        error = HTTPError('https://api.shodan.io/?key=private-key', 403, 'private-key', {}, None)
        with patch('shodan_window.urlopen', side_effect=error):
            with self.assertRaises(ValueError) as caught:
                lookup('Pesquisa', 'test', 'private-key')
        self.assertNotIn('private-key', str(caught.exception))
        with patch('shodan_window.urlopen', side_effect=URLError('private-key')):
            with self.assertRaises(ValueError) as caught:
                lookup('IP', '1.1.1.1', 'private-key')
        self.assertNotIn('private-key', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
