"""Read image metadata locally with ExifTool, without changing the source."""
import json
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from sherlock_window import run_process
from system_install import package_install_command


def read_metadata(path):
    source = Path(path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError('Selecione um arquivo de imagem.')
    executable = shutil.which('exiftool')
    if not executable:
        raise ValueError('ExifTool ausente. No Kali: sudo apt install libimage-exiftool-perl')
    result = subprocess.run([executable, '-j', '-G1', '-a', '-s', str(source)],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'Falha ao ler os metadados.')
    records = json.loads(result.stdout)
    if not records or not isinstance(records[0], dict):
        raise ValueError('Nenhum metadado retornado.')
    return records[0]


class MetadataWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('Metadados de imagem · ExifTool')
        self.geometry('920x650')
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.busy = False
        self.installing = False
        self.data = None
        self.path = tk.StringVar()
        self.status = tk.StringVar(value='Carregue uma imagem para consultar os metadados locais.')
        frame = ttk.Frame(self, padding=12)
        frame.pack(fill='both', expand=True)
        bar = ttk.Frame(frame)
        bar.pack(fill='x')
        self.load_button = ttk.Button(bar, text='Carregar imagem', style='Start.TButton', command=self.load)
        self.load_button.pack(side='left')
        self.install_button = ttk.Button(bar, text='Instalar ExifTool (Kali)', style='Accent.TButton', command=self.install)
        self.install_button.pack(side='left', padx=6)
        ttk.Button(bar, text='Exportar JSON', style='Brute.TButton', command=self.export).pack(side='left')
        ttk.Label(frame, textvariable=self.path, wraplength=850).pack(anchor='w', pady=8)
        ttk.Label(frame, text='EXIF, GPS, camera, datas, dimensoes, XMP e IPTC quando presentes. A imagem original e preservada.',
                  wraplength=850).pack(anchor='w', pady=(0, 8))
        self.output = ScrolledText(frame, wrap='word', state='disabled')
        self.output.pack(fill='both', expand=True)
        ttk.Label(frame, textvariable=self.status, wraplength=850).pack(anchor='w', pady=8)
        self.poll_id = self.after(100, self.poll)
        self.protocol('WM_DELETE_WINDOW', self.close)

    def set_busy(self, value):
        self.busy = value
        for button in (self.load_button, self.install_button):
            button.configure(state='disabled' if value else 'normal')

    def load(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(parent=self, title='Carregar imagem', filetypes=[
            ('Imagens', '*.jpg *.jpeg *.png *.webp *.tif *.tiff *.heic *.avif *.gif *.bmp'), ('Todos os arquivos', '*.*')])
        if not path:
            return
        self.path.set(path)
        self.data = None
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        self.set_busy(True)
        self.status.set('Lendo metadados...')

        def worker():
            try:
                self.events.put(('metadata', read_metadata(path)))
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def install(self):
        if self.busy:
            return
        args = package_install_command(self, 'ExifTool', 'libimage-exiftool-perl')
        if not args:
            return
        self.installing = True
        self.stop_event.clear()
        self.set_busy(True)
        self.status.set('Aguardando instalacao autenticada do ExifTool...')
        threading.Thread(target=run_process, args=(args, self.stop_event, self.events, 'ExifTool'), daemon=True).start()

    def export(self):
        if self.data is None:
            return messagebox.showinfo('Metadados', 'Carregue uma imagem primeiro.', parent=self)
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.json', title='Exportar metadados')
        if path:
            try:
                if Path(path).resolve() == Path(self.path.get()).resolve():
                    raise ValueError('Escolha um arquivo diferente da imagem original.')
                Path(path).write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding='utf-8')
            except (OSError, ValueError) as exc:
                messagebox.showerror('Metadados', str(exc), parent=self)

    def poll(self):
        for _ in range(200):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'log':
                continue
            self.set_busy(False)
            if kind == 'metadata':
                self.data = value
                self.output.configure(state='normal')
                self.output.delete('1.0', 'end')
                self.output.insert('end', json.dumps(value, ensure_ascii=False, indent=2))
                self.output.configure(state='disabled')
                self.status.set(f'{len(value)} campos encontrados. Campos ausentes nao sao inferidos.')
            elif kind == 'error':
                self.status.set(value)
            elif kind == 'done':
                self.installing = False
                self.status.set('ExifTool instalado. Carregue uma imagem.' if value == 0 else 'Instalacao nao concluida.')
        self.poll_id = self.after(100, self.poll)

    def close(self):
        if self.installing:
            self.stop_event.set()
            self.after(100, self.close)
            return
        self.after_cancel(self.poll_id)
        self.destroy()
