"""Local GUI for authorized Sherlock username searches."""
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import uuid
from system_install import package_install_command


def build_command(executable, username, output_dir):
    username = username.strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', username):
        raise ValueError('Informe um nome de usuário válido (letras, números, ponto, hífen ou sublinhado).')
    output_dir = Path(output_dir).expanduser().resolve()
    return [executable, '--no-color', '--output', str(output_dir/(username+'.txt')), username]


def run_process(args, stop, events):
    proc = None
    returncode = None
    try:
        options = {'start_new_session': True} if os.name != 'nt' else {
            'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                errors='replace', **options)

        def read_output():
            for line in proc.stdout:
                events.put(('log', line))
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        interrupted = None
        while proc.poll() is None:
            if stop.is_set():
                if interrupted is None:
                    interrupted = time.monotonic()
                    if os.name == 'nt':
                        proc.terminate()
                    else:
                        os.killpg(proc.pid, signal.SIGINT)
                elif time.monotonic() - interrupted > 3:
                    proc.kill()
            time.sleep(0.1)
        returncode = proc.returncode
        reader.join(timeout=2)
        if stop.is_set():
            events.put(('log', '\nBusca interrompida pelo usuário.\n'))
        events.put(('done', returncode))
    except (OSError, ValueError) as exc:
        events.put(('log', f'Falha ao executar Sherlock: {exc}\n'))
        events.put(('done', None))
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout:
                proc.stdout.close()


class SherlockWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('Sherlock · busca de perfis por usuário')
        self.geometry('800x560')
        self.minsize(600, 420)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.installing = False
        self.executable = tk.StringVar(value=shutil.which('sherlock') or shutil.which('sherlock.exe') or '')
        self.username = tk.StringVar()
        self.output_dir = None

        frame = ttk.Frame(self, padding=14)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        ttk.Label(frame, text='Busca perfis públicos associados a um nome de usuário.').grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(0, 8))
        ttk.Label(frame, text='Executável Sherlock').grid(row=1, column=0, sticky='w', padx=(0, 8))
        self.exe_entry = ttk.Entry(frame, textvariable=self.executable)
        self.exe_entry.grid(row=1, column=1, sticky='ew', pady=4)
        self.exe_button = ttk.Button(frame, text='Selecionar…', command=self.browse_executable)
        self.exe_button.grid(row=1, column=2, padx=(8, 0))
        ttk.Label(frame, text='Nome de usuário').grid(row=2, column=0, sticky='w', padx=(0, 8))
        self.username_entry = ttk.Entry(frame, textvariable=self.username)
        self.username_entry.grid(row=2, column=1, columnspan=2, sticky='ew', pady=4)
        ttk.Label(frame, text='A busca consulta serviços online; resultados são indícios e podem conter falsos positivos.').grid(
            row=3, column=0, columnspan=3, sticky='w', pady=6)
        bar = ttk.Frame(frame)
        bar.grid(row=4, column=0, columnspan=3, sticky='new', pady=6)
        self.start_button = ttk.Button(bar, text='Iniciar busca', command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(bar, text='Parar', command=self.stop, state='disabled')
        self.stop_button.pack(side='left', padx=6)
        self.output = ScrolledText(frame, wrap='word', state='disabled')
        self.output.grid(row=5, column=0, columnspan=3, sticky='nsew', pady=(8, 0))
        frame.rowconfigure(5, weight=1)
        self.status = tk.StringVar(value='Pronto' if self.executable.get() else
                                   'Sherlock não encontrado: instale ou selecione o executável.')
        ttk.Label(frame, textvariable=self.status, wraplength=700).grid(
            row=6, column=0, columnspan=3, sticky='w', pady=(8, 0))
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.after(100, self.poll)

    def browse_executable(self):
        path = filedialog.askopenfilename(parent=self, title='Selecione o executável Sherlock')
        if path:
            self.executable.set(path)

    def append(self, text):
        self.output.configure(state='normal')
        self.output.insert('end', text)
        self.output.see('end')
        self.output.configure(state='disabled')

    def start(self):
        if self.running:
            return
        executable = shutil.which(self.executable.get().strip())
        if not executable:
            args = package_install_command(self, 'Sherlock', 'sherlock')
            if not args:
                return
            self.installing = True
            self.running = True
            self.stop_event.clear()
            self.exe_entry.configure(state='disabled')
            self.username_entry.configure(state='disabled')
            self.exe_button.configure(state='disabled')
            self.start_button.configure(state='disabled')
            self.stop_button.configure(state='normal')
            self.status.set('Aguardando autenticação e instalação do Sherlock…')
            self.append('\nSherlock não está instalado. Solicitando autorização do sistema…\n')
            threading.Thread(target=run_process, args=(args, self.stop_event, self.events), daemon=True).start()
            return
        username = self.username.get().strip()
        folder = (Path.home() / '.config' / 'cyberpm' / 'sherlock-results' /
                  (re.sub(r'[^A-Za-z0-9_.-]', '_', username) + '-' + uuid.uuid4().hex[:8]))
        try:
            args = build_command(executable, username, folder)
            folder.mkdir(parents=True, mode=0o700, exist_ok=False)
        except (ValueError, OSError) as exc:
            messagebox.showerror('Sherlock', str(exc), parent=self)
            return
        self.output_dir = folder
        self.running = True
        self.stop_event.clear()
        self.exe_entry.configure(state='disabled')
        self.username_entry.configure(state='disabled')
        self.exe_button.configure(state='disabled')
        self.start_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Pesquisando — resultados locais: ' + str(folder))
        self.append(f'\nBuscando o nome de usuário “{username}”…\n')
        threading.Thread(target=run_process, args=(args, self.stop_event, self.events), daemon=True).start()

    def stop(self):
        if self.running:
            self.stop_event.set()
            self.status.set('Interrompendo busca…')

    def poll(self):
        for _ in range(200):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'log':
                self.append(value)
            else:
                self.running = False
                self.stop_button.configure(state='disabled')
                if self.installing:
                    self.installing = False
                    executable = shutil.which('sherlock') or shutil.which('sherlock.exe')
                    self.exe_entry.configure(state='normal')
                    self.username_entry.configure(state='normal')
                    self.exe_button.configure(state='normal')
                    self.start_button.configure(state='normal')
                    if value == 0 and executable:
                        self.executable.set(executable)
                        self.status.set('Sherlock instalado. Iniciando a busca…')
                        self.append('\nSherlock instalado com sucesso.\n')
                        self.start()
                    else:
                        self.status.set('A instalação do Sherlock não foi concluída.')
                else:
                    self.exe_entry.configure(state='normal')
                    self.username_entry.configure(state='normal')
                    self.exe_button.configure(state='normal')
                    self.start_button.configure(state='normal')
                    code = '' if value is None else f' (código {value})'
                    self.status.set('Busca encerrada' + code + ' — resultados locais: ' + str(self.output_dir))
        self.after(100, self.poll)

    def close(self):
        self.stop()
        self.destroy()
