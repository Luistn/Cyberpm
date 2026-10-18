from pathlib import Path
import tempfile
import unittest

from scan_inventory import inventory


class ScanInventoryTests(unittest.TestCase):
    def parse(self, xml, exit_code=0):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            path = Path(tmp) / 'nmap.xml'
            path.write_text(xml, encoding='utf-8')
            return inventory(path, 'example.invalid', exit_code)

    def test_open_and_grouped_filtered_states(self):
        result = self.parse('''<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/>
          <ports><extraports state="filtered" count="999"/>
          <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
          <service name="https" product="Example"/></port></ports></host>
          <runstats><finished exit="success"/></runstats></nmaprun>''')
        self.assertTrue(result['complete'])
        self.assertEqual(result['states'], {'filtered': 999, 'open': 1})
        self.assertEqual(result['ports'][0]['port'], 443)
        self.assertEqual(result['addresses'], ['192.0.2.1'])

    def test_finished_scan_with_no_open_ports_is_valid(self):
        result = self.parse('''<nmaprun><host><ports><extraports state="closed" count="1000"/>
          </ports></host><runstats><finished exit="success"/></runstats></nmaprun>''')
        self.assertTrue(result['complete'])
        self.assertEqual(result['ports'], [])

    def test_empty_truncated_no_host_and_timeout_are_inconclusive(self):
        for xml in ('', '<nmaprun>', '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>',
                    '<nmaprun><host><ports/></host><runstats><finished exit="success"/></runstats></nmaprun>'):
            with self.subTest(xml=xml):
                self.assertFalse(self.parse(xml)['complete'])
        xml = '''<nmaprun><host><ports><extraports state="filtered" count="1000"/></ports>
          </host><runstats><finished exit="success"/></runstats></nmaprun>'''
        self.assertFalse(self.parse(xml, 124)['complete'])


if __name__ == '__main__':
    unittest.main()
