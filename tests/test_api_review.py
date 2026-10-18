import json
import unittest
from api_probe import invalid_cpf_urls, response_signals


class ApiReviewTests(unittest.TestCase):
    def test_personal_values_never_returned(self):
        signals = response_signals(json.dumps({'email': 'private-value', 'nested': [{'password': 'secret-value'}]}))
        self.assertIn('credenciais/tokens', str(signals))
        self.assertNotIn('private-value', str(signals))
        self.assertNotIn('secret-value', str(signals))

    def test_invalid_cpf_only_declared_get_in_scope(self):
        schema = {'servers': [{'url': '/api'}], 'paths': {
            '/lookup': {'get': {'parameters': [{'name': 'cpf', 'in': 'query', 'required': True}]}},
            '/recover': {'post': {'parameters': [{'name': 'cpf', 'in': 'query'}]}},
            '/users/{id}': {'get': {'parameters': [{'name': 'cpf', 'in': 'query'}]}}}}
        self.assertEqual(invalid_cpf_urls('https://example.com', schema), [
            'https://example.com/api/lookup?cpf=22222222',
            'https://example.com/api/lookup?cpf=22222222222'])
        schema['servers'] = [{'url': 'https://other.example'}]
        self.assertEqual(invalid_cpf_urls('https://example.com', schema), [])

    def test_required_other_parameters_are_not_guessed(self):
        schema = {'paths': {'/lookup': {'get': {'parameters': [
            {'name': 'cpf', 'in': 'query'}, {'name': 'token', 'in': 'query', 'required': True}]}}}}
        self.assertEqual(invalid_cpf_urls('https://example.com', schema), [])

    def test_error_details_signal(self):
        self.assertTrue(response_signals('Traceback (most recent call last):'))
        self.assertEqual(response_signals('{"status":"ok"}'), [])
