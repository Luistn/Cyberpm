import tempfile
import unittest
from pathlib import Path

from cve_inventory import SOURCES, collect, save


class CveInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def complete_sources(self):
        for paths in SOURCES.values():
            self.write(paths[0], b'')

    def test_missing_evidence_always_produces_diagnostic(self):
        result = collect(self.root)
        text = save(self.root, result)
        self.assertEqual(result['ids'], [])
        self.assertTrue(result['partial'])
        self.assertIn('Nenhuma referência', text)
        self.assertIn('Nuclei: 0 arquivo(s)', text)
        self.assertTrue((self.root / '10_cves/status.json').exists())
        self.assertFalse(result['catalog_lookup'])

    def test_complete_outputs_with_no_ids_are_not_findings(self):
        self.complete_sources()
        result = collect(self.root)
        self.assertFalse(result['partial'])
        self.assertEqual(result['ids'], [])
        self.assertIn('não comprova ausência', save(self.root, result))

    def test_ids_are_deduplicated_and_keep_original_sources(self):
        self.complete_sources()
        self.write('09_vulns/nuclei.txt', b'cve-2026-12345 CVE-2026-12345')
        self.write('29_js/retire.json', b'{"CVE": ["CVE-2026-12345"]}')
        result = collect(self.root)
        self.assertEqual(result['ids'], ['CVE-2026-12345'])
        self.assertEqual(len(result['evidence']), 2)
        save(self.root, result)
        self.assertIn('29_js/retire.json', (self.root / '10_cves/cves.txt').read_text())

    def test_expired_deadline_returns_inconclusive_summary(self):
        self.complete_sources()
        self.write('09_vulns/nuclei.txt', b'CVE-2026-12345')
        result = collect(self.root, seconds=0)
        self.assertTrue(result['partial'])
        self.assertEqual(result['ids'], [])
        self.assertIn('limite de tempo', save(self.root, result))

    def test_byte_limit_and_tool_failure_preserve_partial_ids(self):
        self.complete_sources()
        self.write('09_vulns/nuclei.txt', b'CVE-2026-12345\n' + b'x' * 100)
        self.write('09_vulns/nuclei.exec.txt', b'estado=encerrado\ncodigo=124\n')
        result = collect(self.root, max_bytes=32)
        self.assertTrue(result['partial'])
        self.assertEqual(result['ids'], ['CVE-2026-12345'])
        text = save(self.root, result)
        self.assertIn('limite de leitura', text)
        self.assertIn('saída parcial', text)

    def test_id_split_across_read_chunks(self):
        self.complete_sources()
        self.write('09_vulns/nuclei.txt', b'x' * 65530 + b' CVE-2026-12345678\n')
        self.assertEqual(collect(self.root)['ids'], ['CVE-2026-12345678'])

    def test_nmap_host_timeout_is_partial_even_with_zero_exit(self):
        self.complete_sources()
        self.write('02_portas/nmap.exec.txt', b'estado=encerrado\ncodigo=0\n')
        self.write('02_portas/scan_status.json', b'{"complete": false}')
        result = collect(self.root)
        self.assertTrue(result['partial'])
        self.assertIn('inventário Nmap incompleto', save(self.root, result))
