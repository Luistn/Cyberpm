import queue
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hydra_window import form_command, download_command, save_wordlist


class HydraTests(unittest.TestCase):
    def test_form_preserves_paths_and_options_as_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            words = Path(folder) / 'words with spaces.txt'
            save_wordlist(words, 'pass one\npass two\npass one\n')
            self.assertEqual(words.read_text(), 'pass one\npass two\n')
            with patch('hydra_window.shutil.which', return_value='hydra'):
                args = form_command('hydra', 'localhost', 'ssh', 'test', str(words), '2222', '2', '1')
            self.assertEqual(args[args.index('-P') + 1], str(words.resolve()))
            self.assertEqual(args[-2:], ['localhost', 'ssh'])
            self.assertIn('-f', args)
            self.assertEqual(args[args.index('-s') + 1], '2222')

    def test_invalid_inputs_do_not_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            words = Path(folder) / 'words.txt'
            save_wordlist(words, 'test')
            for target, tasks, port in [('https://host/login', '4', ''),
                                        ('-M', '4', ''), ('host', '0', ''),
                                        ('host', '4', '99999')]:
                with self.subTest(target=target, tasks=tasks, port=port), self.assertRaises(ValueError):
                    form_command('hydra', target, 'ssh', 'user', str(words), port, tasks)
            with self.assertRaises(ValueError):
                form_command('hydra', 'host', 'http-post-form', 'user', str(words))
            with self.assertRaises(ValueError):
                save_wordlist(words, '\n\n')
            self.assertEqual(words.read_text(), 'test\n')

    def test_download_requires_http_and_uses_argument_array(self):
        with patch('hydra_window.shutil.which', return_value='wget'):
            args = download_command('https://example.org/list.txt?a=1&b=2', 'words file.txt')
            self.assertEqual(args[-2:], ['--', 'https://example.org/list.txt?a=1&b=2'])
            self.assertEqual(args[args.index('-O') + 1], 'words file.txt')
            with self.assertRaises(ValueError):
                download_command('file:///etc/passwd', 'words.txt')


if __name__ == '__main__':
    unittest.main()
