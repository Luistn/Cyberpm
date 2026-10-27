import queue
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from john_window import command, run_process


class JohnTests(unittest.TestCase):
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
