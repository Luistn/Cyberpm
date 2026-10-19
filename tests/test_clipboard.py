import tkinter as tk
import unittest
from cyberpm_gui import Cyberpm


class ClipboardTests(unittest.TestCase):
    def test_copy_repeatedly_across_windows_and_disabled_text(self):
        try:
            root=tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        root.withdraw()
        app=Cyberpm.__new__(Cyberpm); app.root=root
        try:
            for value in ('first','second','third'):
                window=tk.Toplevel(root); window.withdraw()
                text=tk.Text(window,exportselection=False)
                text.insert('1.0',value+' extra')
                text.configure(state='disabled')
                text.tag_add('sel','1.0',f'1.{len(value)}')
                for _ in range(2):
                    self.assertEqual(app.copy_panel(widget=text),'break')
                    root.update()
                    self.assertEqual(root.clipboard_get(),value)
                window.destroy()
        finally:
            root.destroy()
