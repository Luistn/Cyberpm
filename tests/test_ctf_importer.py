import json
from pathlib import Path
import stat
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch
import zipfile

from ctf_importer import import_package, package_info, safe_member, write_template
from ctf_import_window import ImportCtfWindow
from ctf_window import CtfWindow


class PackageTests(unittest.TestCase):
    def test_template_import_preserves_readme_url_commands_and_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'modelo.zip'
            write_template(source)
            original = source.read_bytes()
            info = import_package(source,root/'imports')
            self.assertEqual(info['title'],'Exemplo de importação')
            self.assertIn('Leia evidencia.txt',info['readme'])
            self.assertEqual(info['url'],'http://127.0.0.1:8765/')
            self.assertEqual(info['setup'],['python3 -m http.server 8765 --bind 127.0.0.1'])
            self.assertEqual(len(info['files']),4)
            self.assertEqual(source.read_bytes(),original)

    def test_folder_and_nested_zip_without_manifest_are_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root/'laboratorio';folder.mkdir()
            (folder/'README.md').write_text('Enunciado externo')
            (folder/'capture.pcap').write_bytes(b'test')
            info = import_package(folder,root/'imports')
            self.assertEqual(info['title'],'laboratorio')
            self.assertIn('Enunciado externo',info['readme'])
            archive = root/'nested.zip'
            with zipfile.ZipFile(archive,'w') as zipped:
                zipped.writestr('./','')
                zipped.writestr('lab/README.txt','Leia as instruções do laboratório.')
                zipped.writestr('lab/compose.yaml','services: {}')
            info = import_package(archive,root/'imports')
            self.assertEqual(info['root'].name,'lab')
            self.assertEqual(info['setup'],['docker compose up --build'])

    def test_traversal_absolute_drive_and_symlink_entries_are_rejected(self):
        for name in ['../outside','/outside','C:/outside','..\\outside']:
            with self.assertRaises(ValueError):
                safe_member(name)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index,name in enumerate(['../outside','safe/../../outside','C:/outside']):
                source = root/f'invalid-{index}.zip'
                with zipfile.ZipFile(source,'w') as zipped:
                    zipped.writestr('first.txt','safe')
                    zipped.writestr(name,'escape')
                with self.assertRaises(ValueError):
                    import_package(source,root/'imports')
                self.assertEqual(list((root/'imports').iterdir()),[])
            source = root/'link.zip'
            entry = zipfile.ZipInfo('link');entry.create_system=3
            entry.external_attr = (stat.S_IFLNK|0o777)<<16
            with zipfile.ZipFile(source,'w') as zipped:
                zipped.writestr(entry,'/outside')
            with self.assertRaises(ValueError):
                import_package(source,root/'imports')

    def test_size_limit_cancellation_and_duplicate_entries_clean_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);source=root/'large.zip';destination=root/'imports'
            with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED) as zipped:
                zipped.writestr('large.txt',b'a'*2_000_000)
            with self.assertRaises(ValueError):
                import_package(source,destination,limit_mib=1)
            self.assertEqual(list(destination.iterdir()),[])
            stop=threading.Event();stop.set()
            with self.assertRaises(InterruptedError):
                import_package(source,destination,stop=stop)
            self.assertEqual(list(destination.iterdir()),[])
            with zipfile.ZipFile(source,'w') as zipped:
                zipped.writestr('A.txt','a');zipped.writestr('a.txt','b')
            with self.assertRaises(ValueError):
                import_package(source,destination)
            self.assertEqual(list(destination.iterdir()),[])

    def test_manifest_is_data_and_invalid_url_does_not_leave_an_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'data.zip';destination=root/'imports'
            manifest={'title':'Externo','setup':['touch should-not-exist']}
            with zipfile.ZipFile(source,'w') as zipped:
                zipped.writestr('ctf.json',json.dumps(manifest))
            info=import_package(source,destination)
            self.assertEqual(info['setup'],['touch should-not-exist'])
            self.assertFalse((info['root']/'should-not-exist').exists())
            manifest['url']='file:///private'
            with zipfile.ZipFile(source,'w') as zipped:
                zipped.writestr('ctf.json',json.dumps(manifest))
            before=set(destination.iterdir())
            with self.assertRaises(ValueError):
                import_package(source,destination)
            self.assertEqual(set(destination.iterdir()),before)

    def test_template_failed_write_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'original.zip';path.write_bytes(b'original')
            with patch('ctf_importer.os.replace',side_effect=OSError('teste')):
                with self.assertRaises(OSError):
                    write_template(path)
            self.assertEqual(path.read_bytes(),b'original')
            self.assertEqual(list(Path(directory).iterdir()),[path])


class ImportWindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root=tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.withdraw()
        self.directory=tempfile.TemporaryDirectory()
        self.files=[];self.urls=[]
        self.window=ImportCtfWindow(self.root,lambda *args:self.files.append(args),self.urls.append)
        self.window.withdraw()

    def tearDown(self):
        self.window.close()
        self.root.destroy()
        self.directory.cleanup()

    def test_single_file_open_routes_to_tool_and_url_is_prepared(self):
        path=Path(self.directory.name)/'trafego.pcap';path.write_bytes(b'capture')
        self.window.source.set(str(path))
        self.window.start()
        deadline=time.monotonic()+3
        while self.window.busy and time.monotonic()<deadline:
            self.root.update();time.sleep(.02)
        self.assertFalse(self.window.busy)
        self.assertEqual(self.window.tool.get(),'Capturas')
        self.window.send_file()
        self.assertEqual(self.files[-1],('Capturas',str(path.resolve())))
        self.window.url.set('http://localhost:8765/')
        self.window.send_url()
        self.assertEqual(self.urls,['http://localhost:8765/'])

    def test_imported_readme_and_setup_are_visible_and_copyable(self):
        root=Path(self.directory.name);source=root/'modelo.zip';write_template(source)
        info=import_package(source,root/'imports')
        self.window.display(info)
        self.assertIn('ENUNCIADO / README',self.window.document.get('1.0','end'))
        with patch('ctf_import_window.show_document') as show:
            self.window.commands()
        self.assertIn('http.server 8765',show.call_args.args[3])

    def test_main_panel_reuses_importer_and_populates_tools(self):
        panel=CtfWindow(self.root);panel.withdraw()
        try:
            imported=panel.open_importer();imported.withdraw()
            self.assertIs(panel.open_importer(),imported)
            panel.open_imported_file('Logs','/tmp/external.log')
            self.assertEqual(panel.current_tab,'Logs')
            self.assertEqual(panel.log.get(),'/tmp/external.log')
            panel.use_imported_url('http://localhost:8765/busca?q=Redes')
            self.assertEqual(panel.current_tab,'Web e sessão')
            self.assertEqual(panel.cookie.get(),'')
            panel.open_imported_file('John · hashes','/tmp/hashes.txt')
            panel.import_john.withdraw()
            self.assertEqual(panel.import_john.hashes.get(),'/tmp/hashes.txt')
        finally:
            panel.close()


if __name__=='__main__':
    unittest.main()
