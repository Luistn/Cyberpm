import tkinter as tk
import unittest

from cyberpm_gui import Cyberpm


class LogLayoutTests(unittest.TestCase):
    def test_mapped_log_has_space_and_continues_after_clear(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest('Tk display unavailable: '+str(exc))
        root.withdraw()
        try:
            # Map for real geometry calculations without showing a visible window.
            root.attributes('-alpha', 0)
            root.geometry('1000x800')
            app = Cyberpm.__new__(Cyberpm)
            app.root = root
            app.F = 'Arial'
            app.phase_rows = {}
            app.out_label = tk.StringVar(root, value='Saída: teste')
            app.phase_messages = {1: ['evidence preserved']}
            app.sec_right(root)
            root.deiconify()
            root.update()
            self.assertTrue(app.log.winfo_ismapped())
            self.assertEqual(app.log.winfo_manager(), 'grid')
            self.assertEqual(app.log.master, app.log.grid_info()['in'])
            self.assertGreater(app.log.winfo_height(), 150)
            self.assertGreater(app.log.winfo_width(), 300)
            app.append_log('[·] first message\n')
            root.update_idletasks()
            self.assertIsNotNone(app.log.dlineinfo('1.0'))
            self.assertIn('first message', app.log.get('1.0', 'end'))
            app.clear_log()
            self.assertEqual(app.log.get('1.0', 'end-1c'), '')
            app.append_log('[!] next message\n')
            self.assertIn('next message', app.log.get('1.0', 'end'))
            self.assertEqual(app.phase_messages, {1: ['evidence preserved']})
            root.geometry('850x620')
            root.update()
            self.assertGreater(app.log.winfo_height(), 100)
        finally:
            root.destroy()
