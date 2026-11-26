import queue
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from john_window import JohnWindow, command, pasted_hash_problem, raw_hash_hint, run_process


class JohnTests(unittest.TestCase):
    def test_pasted_crypt_reports_exact_excess_and_invalid_positions(self):
        prefix = '$6$rounds=5000$sal$'
        digest = 'a' * 86
        self.assertEqual(pasted_hash_problem(prefix+digest, ''), '')
        problem = pasted_hash_problem(prefix+digest+'!x', '')
        self.assertIn('2 caractere(s) a mais', problem)
        self.assertIn(f'posição {len(prefix+digest)+1}', problem)
        self.assertIn("'!'", problem)
        self.assertIn(f'posição {len(prefix)+1}', pasted_hash_problem(prefix+'!'+digest[1:], ''))
        self.assertIn('faltam 2', pasted_hash_problem(prefix+digest[:-2], ''))

    def test_pasted_bcrypt_and_selected_hex_format_check_length(self):
        bcrypt = '$2b$12$' + 'a' * 53
        self.assertEqual(pasted_hash_problem(bcrypt, ''), '')
        self.assertIn('posição 61', pasted_hash_problem(bcrypt+'a', ''))
        self.assertIn('posição 33', pasted_hash_problem('aluno:' + 'a' * 33, 'raw-md5'))

    def test_untyped_hex_reports_only_a_hint(self):
        text = 'a' * 32 + '!'
        self.assertEqual(pasted_hash_problem(text, ''), '')
        self.assertIn('possível(is) caractere(s) a mais a partir da posição 33', raw_hash_hint(text))
        self.assertEqual(raw_hash_hint('a' * 32), '')

    def test_start_reports_extra_character_without_starting_john(self):
        prefix = '$6$sal$'
        hash_text = prefix + 'a' * 86 + '!'
        panel = SimpleNamespace(running=False, executable=Mock(), hashes=Mock(), wordlist=Mock(),
                                format_name=Mock(), pasted_hash=Mock(), status=Mock(), append=Mock())
        panel.format_name.get.return_value = ''
        panel.pasted_hash.get.return_value = hash_text
        with patch('john_window.shutil.which', return_value='/fake/john'), patch('john_window.threading.Thread') as worker:
            JohnWindow.start(panel)
        worker.assert_not_called()
        self.assertIn(f'posição {len(hash_text)}', panel.append.call_args.args[0])
        self.assertEqual(panel.append.call_args.args[1], 'error')

    def test_paths_are_arguments_and_show_uses_same_pot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = root/'hashes with spaces.txt'; hashes.write_text('test')
            words = root/'words & more.txt'; words.write_text('test')
            args = command('john', hashes, words, 'raw-md5', root)
            self.assertIn('--wordlist='+str(words.resolve()),args)
            self.assertEqual(args[-1],str(hashes.resolve()))
            show = command('john',hashes,'','raw-md5',root,True)
            self.assertIn('--show',show)
            self.assertEqual(show[1],args[1])
            self.assertFalse(any(arg.startswith('--wordlist') for arg in show))
            with self.assertRaises(ValueError):
                command('john',hashes,words,'--shell=bad',root)
            with self.assertRaises(ValueError):
                command('john',hashes,root/'missing','','.')

    def test_stop_works_for_silent_process(self):
        events = queue.Queue(); stop = threading.Event()
        worker = threading.Thread(target=run_process,args=(
            [sys.executable,'-c','import time; time.sleep(30)'],stop,events))
        worker.start(); time.sleep(0.3); stop.set(); worker.join(timeout=7)
        self.assertFalse(worker.is_alive())
        messages = list(events.queue)
        self.assertEqual(messages[-1],('done',None))
        self.assertTrue(any('Interrompido' in str(value) for _,value in messages))

    def test_failed_launch_finishes(self):
        events = queue.Queue()
        run_process(['nonexistent-john-cyberpm'],threading.Event(),events)
        self.assertEqual(list(events.queue)[-1],('done',None))


if __name__ == '__main__':
    unittest.main()
