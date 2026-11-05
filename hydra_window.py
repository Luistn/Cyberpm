"""Separate Hydra launcher with streamed output and cancellation."""
import queue
import shlex
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from sherlock_window import run_process


def build_command(executable, arguments):
    """Parse quoted arguments without invoking a shell."""
    executable = shutil.which(executable.strip() or 'hydra')
    if not executable:
        raise ValueError('Hydra não encontrado. Selecione o executável. No Kali/Debian: sudo apt install hydra')
    return [executable, *(shlex.split(arguments) or ['-h'])]


class HydraWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('Hydra · execução independente')
        self.geometry('900x600')
        self.minsize(650, 420)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.executable = tk.StringVar(value=shutil.which('hydra') or '')
        self.arguments = tk.StringVar(value='-h')
        self.status = tk.StringVar(value='Pronto' if self.executable.get() else 'Hydra não encontrado. Selecione o executável. No Kali/Debian: sudo apt install hydra')

        frame = ttk.Frame(self, padding=14)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text='Hydra — use em serviços próprios ou com autorização.').grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(0, 10))
        ttk.Label(frame, text='Executável Hydra').grid(row=1, column=0, sticky='w', padx=(0, 8))
        self.exe_entry = ttk.Entry(frame, textvariable=self.executable)
        self.exe_entry.grid(row=1, column=1, sticky='ew')
        self.browse_button = ttk.Button(frame, text='Selecionar…', command=self.browse)
        self.browse_button.grid(row=1, column=2, padx=(8, 0))
        ttk.Label(frame, text='Argumentos').grid(row=2, column=0, sticky='w', padx=(0, 8))
        self.args_entry = ttk.Entry(frame, textvariable=self.arguments)
        self.args_entry.grid(row=2, column=1, columnspan=2, sticky='ew', pady=8)
        ttk.Label(frame, text='Use -h para ajuda. Coloque caminhos com espaços entre aspas duplas; use / nos caminhos.').grid(
            row=3, column=0, columnspan=3, sticky='w')
        bar = ttk.Frame(frame)
        bar.grid(row=4, column=0, columnspan=3, sticky='ew', pady=10)
        self.start_button = ttk.Button(bar, text='▶ Executar Hydra', command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(bar, text='Parar', command=self.stop, state='disabled')
        self.stop_button.pack(side='left', padx=6)
        self.output = ScrolledText(frame, wrap='word', state='disabled')
        self.output.grid(row=5, column=0, columnspan=3, sticky='nsew')
        frame.rowconfigure(5, weight=1)
        ttk.Label(frame, textvariable=self.status, wraplength=620).grid(
            row=6, column=0, columnspan=3, sticky='w', pady=(8, 0))
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.poll_id = self.after(100, self.poll)

    def browse(self):
        path = filedialog.askopenfilename(parent=self, title='Selecione o executável Hydra')
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
        try:
            args = build_command(self.executable.get(), self.arguments.get())
        except ValueError as exc:
            messagebox.showerror('Hydra', str(exc), parent=self)
            return
        self.running = True
        self.stop_event.clear()
        for widget in (self.exe_entry, self.args_entry, self.browse_button, self.start_button):
            widget.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Hydra em execução…')
        self.append('\nIniciando Hydra…\n')
        threading.Thread(target=run_process, args=(args, self.stop_event, self.events, 'Hydra'), daemon=True).start()

    def stop(self):
        if self.running:
            self.stop_event.set()
            self.status.set('Interrompendo Hydra…')

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
                for widget in (self.exe_entry, self.args_entry, self.browse_button, self.start_button):
                    widget.configure(state='normal')
                self.stop_button.configure(state='disabled')
                self.status.set('Interrompido' if self.stop_event.is_set() else
                                'Falha ao executar' if value is None else f'Encerrado (código {value})')
        self.poll_id = self.after(100, self.poll)

    def close(self):
        self.stop()
        self.after_cancel(self.poll_id)
        self.destroy()
