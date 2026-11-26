import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cyberpm_gui import Cyberpm


class ToolWindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.attributes('-alpha', 0)
        self.app = Cyberpm(self.root)
        self.app.show_main()

    def tearDown(self):
        if hasattr(self, 'root'):
            self.root.destroy()

    def test_tool_guide_and_phase_selector_open(self):
        self.app.open_bounty_guide()
        self.assertTrue(self.app.bounty_window.winfo_exists())
        self.app.sel_phases()
        self.assertIn('Fases', [window.title() for window in self.root.winfo_children()
                                if isinstance(window, tk.Toplevel)])

    def test_phase_tooltip_shows_executor_and_guide_tools(self):
        event = SimpleNamespace(y=0, x_root=0, y_root=0)
        with patch.object(self.app.tree, 'identify_row', return_value=self.app.phase_rows[3]):
            self.app.phase_hover(event)
        text = self.app.phase_tip.winfo_children()[0].cget('text')
        self.assertIn('Ferramentas previstas\nwhatweb', text)
        self.assertIn('Referências do guia\nhttpx, GoWitness', text)

    def test_every_tool_opens_without_network_and_reuses_its_window(self):
        for title in self.app.tool_windows:
            with self.subTest(tool=title):
                window = self.app.tool_windows[title]
                self.app.open_tool_window(title)
                self.root.update_idletasks()
                self.assertEqual(window.state(), 'normal')
                window.withdraw()
                self.app.open_tool_window(title)
                self.assertTrue(window.winfo_exists())
        for action, attribute in (
            (self.app.open_hydra, 'hydra_window'),
            (self.app.open_john, 'john_window'),
            (self.app.open_sherlock, 'sherlock_window'),
            (self.app.open_shodan, 'shodan_window'),
            (self.app.open_metadata, 'metadata_window'),
            (self.app.open_php2shell, 'php2shell_window')):
            with self.subTest(tool=attribute):
                action()
                window = getattr(self.app, attribute)
                self.root.update_idletasks()
                self.assertTrue(window.winfo_exists())
                action()
                self.assertIs(window, getattr(self.app, attribute))

    def test_wordlist_selection_keeps_tool_open(self):
        window = self.app.tool_windows['Brute force']
        self.app.open_tool_window('Brute force')
        with patch('cyberpm_gui.filedialog.askopenfilename', return_value='/tmp/list.txt') as dialog:
            self.app.browse_wl()
        self.assertIs(dialog.call_args.kwargs['parent'], window)
        self.assertEqual(window.state(), 'normal')
        self.assertTrue(self.app.use_wordlist.get())
        self.assertIn('brute force', self.app.brute_btn.cget('text'))

    def test_wordlist_is_not_mixed_with_typed_passwords_and_validation_uses_one(self):
        with tempfile.TemporaryDirectory() as folder:
            words = Path(folder) / 'words.txt'
            words.write_text('first\nsecond\n', encoding='utf-8-sig')
            self.app.target.set('https://example.invalid')
            self.app.brute_url.set('https://example.invalid/login')
            self.app.brute_user.set('test')
            self.app.brute_pw.insert('end', 'stale typed entry')
            self.app.use_wordlist.set(True)
            self.app.brute_wordlist.set(str(words))
            with patch.object(self.app, 'save_prefs'), patch('cyberpm_gui.threading.Thread') as thread:
                self.app.brute_force(validation=True)
            self.assertEqual(thread.call_args.kwargs['args'][2], ['first'])
            self.assertTrue(thread.call_args.kwargs['args'][-1])


if __name__ == '__main__':
    unittest.main()
