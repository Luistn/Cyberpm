import unittest
from osint_lookup import prepare_query, detect_kind


class OsintTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(prepare_query('Placa', 'abc-1234')['value'], 'ABC1234')
        self.assertEqual(prepare_query('Placa', 'abc1d23')['value'], 'ABC1D23')
        self.assertEqual(prepare_query('Telefone', '+55 (11) 99999-1234')['value'], '+5511999991234')
        self.assertEqual(prepare_query('E-mail', 'Pessoa@EXAMPLE.COM')['value'], 'Pessoa@example.com')

    def test_detection_and_domain(self):
        for value, kind in [('Maria Silva', 'Nome'), ('@apelido', 'Usuário'), ('a@example.com', 'E-mail'), ('ABC1D23', 'Placa'), ('+5511999991234', 'Telefone'), ('https://example.com/path', 'Domínio')]:
            self.assertEqual(detect_kind(value), kind)
        self.assertEqual(prepare_query('Domínio', 'https://EXAMPLE.COM/path')['value'], 'example.com')
        self.assertEqual(prepare_query('Usuário', '@apelido')['value'], 'apelido')
        with self.assertRaises(ValueError):
            prepare_query('Usuário', '--help')

    def test_invalid_inputs(self):
        for kind, value in [('Placa', 'ABC123'), ('E-mail', 'a@'), ('Telefone', 'abc12345678'), ('Nome', ''), ('Outro', 'abc')]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                prepare_query(kind, value)

    def test_queries_are_encoded_and_unconfirmed(self):
        result = prepare_query('Nome', 'Maria Silva', 'São Paulo & empresa')
        self.assertIn('%26', result['sources'][0]['url'])
        self.assertEqual(result['evidence'], [])
        self.assertIn('ainda não verificadas', result['status'])
        self.assertTrue(result['created_at'].endswith('+00:00'))


if __name__ == '__main__':
    unittest.main()
