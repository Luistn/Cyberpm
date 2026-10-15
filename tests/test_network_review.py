import subprocess
import unittest
from unittest.mock import patch
from network_review import perform


class NetworkReviewTests(unittest.TestCase):
    def test_mac_failure_restores_link(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[0] == 'macchanger':
                raise subprocess.CalledProcessError(1, args)
        with patch('network_review.shutil.which', return_value='/tool'), patch('network_review.snapshot', return_value={'up': True, 'mac': 'old', 'addresses': []}), patch('network_review.run', side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                perform('random', 'eth0')
        self.assertEqual(calls[-1], ['ip', 'link', 'set', 'dev', 'eth0', 'up'])

    def test_dhcp_unchanged_is_not_change(self):
        state = {'up': True, 'mac': 'old', 'addresses': ['192.0.2.1']}
        with patch('network_review.shutil.which', return_value='/tool'), patch('network_review.snapshot', return_value=state), patch('network_review.run') as run:
            result = perform('renew', 'eth0')
        self.assertIn('permaneceram iguais', result['result'])
        self.assertEqual(run.call_args.args[0], ['dhclient', '-1', 'eth0'])

    def test_invalid_interface_never_runs(self):
        with patch('network_review.run') as run:
            for name in ('lo', 'eth0;id', '', '-x'):
                with self.assertRaises(ValueError): perform('random', name)
            run.assert_not_called()

    def test_missing_tool_never_changes_interface(self):
        with patch('network_review.shutil.which', return_value=None), patch('network_review.run') as run:
            with self.assertRaises(ValueError): perform('random', 'eth0')
            run.assert_not_called()
