"""Local John the Ripper wordlist audits, independent of web scans."""
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText


def command(executable, hashes, wordlist, format_name, directory, show=False):
    hashes = Path(hashes).expanduser().resolve()
    if not hashes.is_file():
        raise ValueError('Selecione um arquivo de hashes existente.')
    format_name = format_name.strip()
    if format_name and not re.fullmatch(r'[A-Za-z0-9_-]+', format_name):
        raise ValueError('Formato inválido. Use o nome reconhecido pelo John, como bcrypt ou raw-md5.')
    directory = Path(directory).resolve()
    args = [executable, '--pot='+str(directory/'john.pot')]
    if format_name:
        args.append('--format='+format_name)
    if show:
        args.append('--show')
    else:
        wordlist = Path(wordlist).expanduser().resolve()
        if not wordlist.is_file():
            raise ValueError('Selecione uma lista de palavras existente e descompactada.')
        args.extend(['--session='+str(directory/'session'), '--wordlist='+str(wordlist)])
    return args + [str(hashes)]


def run_process(args, stop, events):
    """Drain output separately so cancellation also works when John is silent."""
    proc = None
    try:
        options = {'start_new_session': True} if os.name != 'nt' else {
            'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                errors='replace', **options)

        def read():
            for line in proc.stdout:
                events.put(('log', line))
        reader = threading.Thread(target=read, daemon=True)
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
                elif time.monotonic()-interrupted > 3:
                    proc.kill()
            time.sleep(0.1)
        reader.join(timeout=2)
        events.put(('log', '\nInterrompido pelo usuário.\n' if stop.is_set()
                    else f'\nProcesso encerrado (código {proc.returncode}).\n'))
    except (OSError, ValueError) as exc:
        events.put(('log', f'Falha ao executar John: {exc}\n'))
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout:
                proc.stdout.close()
        events.put(('done', None))


class JohnWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('John the Ripper · auditoria local de hashes')
        self.geometry('800x580'); self.minsize(620,440)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.directory = None
        self.inputs = None
        self.executable = tk.StringVar(value=shutil.which('john') or shutil.which('john.exe') or '')
        self.hashes = tk.StringVar(); self.wordlist = tk.StringVar()
        self.format_name = tk.StringVar()
        frame = ttk.Frame(self, padding=14); frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1); frame.rowconfigure(7, weight=1)
        ttk.Label(frame, text='Auditoria offline de hashes próprios ou autorizados.').grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(0,8))
        self.fields = []
        for row, label, variable in ((1,'Executável John',self.executable),
                                     (2,'Arquivo de hashes',self.hashes),
                                     (3,'Lista de palavras',self.wordlist)):
            ttk.Label(frame,text=label).grid(row=row,column=0,sticky='w',padx=(0,8))
            entry = ttk.Entry(frame,textvariable=variable)
            entry.grid(row=row,column=1,sticky='ew',pady=4)
            button = ttk.Button(frame,text='Selecionar…',command=lambda v=variable:self.browse(v))
            button.grid(row=row,column=2,padx=(8,0))
            self.fields.extend((entry,button))
        ttk.Label(frame,text='Formato (opcional)').grid(row=4,column=0,sticky='w')
        entry = ttk.Entry(frame,textvariable=self.format_name)
        entry.grid(row=4,column=1,sticky='ew',pady=4); self.fields.append(entry)
        ttk.Label(frame,text='Vazio = detecção automática. No Kali: sudo apt install john').grid(
            row=5,column=0,columnspan=3,sticky='w',pady=6)
        bar = ttk.Frame(frame); bar.grid(row=6,column=0,columnspan=3,sticky='ew',pady=6)
        self.start_button = ttk.Button(bar,text='Iniciar',command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(bar,text='Parar',command=self.stop,state='disabled')
        self.stop_button.pack(side='left',padx=6)
        self.show_button = ttk.Button(bar,text='Mostrar recuperadas',command=lambda:self.start(show=True),state='disabled')
        self.show_button.pack(side='left')
        self.output = ScrolledText(frame,wrap='word',state='disabled')
        self.output.grid(row=7,column=0,columnspan=3,sticky='nsew',pady=(8,0))
        self.status = tk.StringVar(value='Pronto' if self.executable.get() else 'John não encontrado: instale ou selecione o executável.')
        ttk.Label(frame,textvariable=self.status,wraplength=700).grid(row=8,column=0,columnspan=3,sticky='w',pady=(8,0))
        self.protocol('WM_DELETE_WINDOW',self.close)
        self.bind('<Destroy>',self.on_destroy,add='+')
        self.after(100,self.poll)

    def browse(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:
            variable.set(path)

    def append(self, text):
        self.output.configure(state='normal'); self.output.insert('end',text)
        self.output.see('end'); self.output.configure(state='disabled')

    def start(self, show=False):
        if self.running:
            return
        try:
            if show:
                executable, hashes, wordlist, format_name = self.inputs
                directory = self.directory
            else:
                executable = shutil.which(self.executable.get().strip())
                if not executable:
                    raise ValueError('John não encontrado. No Kali, instale com sudo apt install john ou selecione o executável.')
                hashes, wordlist, format_name = self.hashes.get(), self.wordlist.get(), self.format_name.get()
                directory = Path.home()/'.config'/'cyberpm'/'john-results'/uuid.uuid4().hex
            args = command(executable,hashes,wordlist,format_name,directory,show)
            directory.mkdir(parents=True,mode=0o700,exist_ok=True)
        except (ValueError,OSError,TypeError) as exc:
            messagebox.showerror('John the Ripper',str(exc),parent=self); return
        self.directory = directory
        self.inputs = (executable,str(Path(hashes).expanduser().resolve()),wordlist,format_name)
        self.running = True; self.stop_event.clear()
        for field in self.fields:
            field.configure(state='disabled')
        self.start_button.configure(state='disabled'); self.show_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Executando — resultados locais: '+str(directory))
        self.append('\nMostrando recuperadas…\n' if show else '\nIniciando auditoria por lista de palavras…\n')
        threading.Thread(target=run_process,args=(args,self.stop_event,self.events),daemon=True).start()

    def stop(self):
        self.stop_event.set()
        if self.running:
            self.status.set('Interrompendo…')

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
                for field in self.fields:
                    field.configure(state='normal')
                self.start_button.configure(state='normal'); self.show_button.configure(state='normal')
                self.stop_button.configure(state='disabled')
                self.status.set('Encerrado — resultados locais: '+str(self.directory))
        self.after(100,self.poll)

    def on_destroy(self, event):
        if event.widget is self:
            self.stop_event.set()

    def close(self):
        self.stop(); self.destroy()
