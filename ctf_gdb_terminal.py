"""Small interactive GDB console hosted inside the CTF workstation."""
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText


class GdbTerminal(tk.Toplevel):
    def __init__(self, parent, binary):
        super().__init__(parent)
        self.binary = Path(binary).resolve(strict=True)
        self.title('CTF · terminal interativo GDB')
        self.geometry('1060x780')
        self.minsize(760, 560)
        self.events = queue.Queue()
        self.process = None
        self.pty_fd = None
        self.reader = None
        self.closed = False
        self.commands = []
        self.last_program_input = ''
        self.string_results = []
        self.gdb_parse_buffer = ''
        self.capture_arguments = False
        self.candidate = tk.StringVar(value='Chave candidata: aguardando breakpoint em strcmp')
        self.status = tk.StringVar(value='GDB iniciando…')

        frame = ttk.Frame(self, padding=10)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Terminal interativo · GDB',
                  font=('TkDefaultFont', 14, 'bold')).pack(anchor='w')
        ttk.Label(frame,
                  text=f'Arquivo ELF: {self.binary}\nCtrl+D abre a ajuda DeepSeek com a saída deste terminal. O programa só roda quando você clicar Executar ou digitar run.',
                  wraplength=1000, justify='left').pack(anchor='w', pady=(4, 7))
        ttk.Label(frame, textvariable=self.candidate, font=('TkDefaultFont', 12, 'bold')).pack(anchor='w', pady=(0, 6))
        self.output = ScrolledText(frame, wrap='word', state='disabled', height=24,
                                   font=('TkFixedFont', 10))
        self.output.tag_configure('key', foreground='#123b20', background='#baf3cb',
                                  font=('TkFixedFont', 12, 'bold'))
        self.output.pack(fill='both', expand=True)

        row = ttk.Frame(frame)
        row.pack(fill='x', pady=(7, 3))
        ttk.Button(row, text='Executar (run)', command=lambda: self.send_command('run', program_input=False)).pack(side='left')
        ttk.Button(row, text='Ver argumentos de strcmp', command=self.inspect_compare).pack(side='left', padx=5)
        ttk.Button(row, text='Continuar', command=lambda: self.send_command('continue', program_input=False)).pack(side='left')
        ttk.Button(row, text='Interromper', command=self.interrupt).pack(side='left', padx=5)

        command_row = ttk.Frame(frame)
        command_row.pack(fill='x')
        self.command = tk.StringVar()
        entry = ttk.Entry(command_row, textvariable=self.command)
        entry.pack(side='left', fill='x', expand=True)
        entry.bind('<Return>', self.send_entry)
        ttk.Button(command_row, text='Enviar linha', command=self.send_entry).pack(side='left', padx=(7, 0))
        ttk.Label(frame, textvariable=self.status).pack(anchor='w', pady=(5, 0))
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.bind('<Destroy>', self.on_destroy, add='+')
        self.start_gdb()
        self.after(80, self.poll)
        entry.focus_set()

    def start_gdb(self):
        argv = ['gdb', '--quiet', '--nx', str(self.binary)]
        try:
            if os.name == 'posix':
                import pty
                master, slave = pty.openpty()
                try:
                    self.process = subprocess.Popen(argv, cwd=str(self.binary.parent),
                        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                        start_new_session=True)
                finally:
                    os.close(slave)
                self.pty_fd = master
                self.reader = threading.Thread(target=self.read_pty, daemon=True)
            else:
                self.process = subprocess.Popen(argv, cwd=str(self.binary.parent),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                self.reader = threading.Thread(target=self.read_pipe, daemon=True)
            self.reader.start()
            self.status.set('GDB aberto. Breakpoint em strcmp será configurado automaticamente.')
            self.after(300, self.configure_breakpoint)
        except (OSError, ValueError) as exc:
            self.append(f'Não foi possível iniciar GDB: {exc}\n')
            self.status.set('Falha ao iniciar GDB.')

    def configure_breakpoint(self):
        if self.closed or self.process is None or self.process.poll() is not None:
            return
        for command in ('set pagination off', 'set breakpoint pending on', 'break strcmp',
                        'commands', 'silent', 'printf "\\n[CTF] Argumentos de strcmp:\\n"',
                        'x/s $rdi', 'x/s $rsi', 'end'):
            self.send_command(command, program_input=False, log=False)
        self.status.set('Pronto. Clique Executar; no prompt da chave, digite qualquer texto para inspecionar a comparação.')

    def read_pty(self):
        while not self.closed and self.pty_fd is not None:
            try:
                data = os.read(self.pty_fd, 4096)
                if not data:
                    break
                self.events.put(('text', data.decode('utf-8', errors='replace')))
            except OSError:
                break
        self.events.put(('eof', None))

    def read_pipe(self):
        try:
            for line in self.process.stdout:
                self.events.put(('text', line))
        except (OSError, ValueError):
            pass
        self.events.put(('eof', None))

    def append(self, text, tag=None):
        self.output.configure(state='normal')
        self.output.insert('end', text, tag)
        if int(self.output.index('end-1c').split('.')[0]) > 20000:
            self.output.delete('1.0', '5001.0')
        self.output.see('end')
        self.output.configure(state='disabled')

    def send_entry(self, _event=None):
        line = self.command.get()
        if line.strip():
            self.send_command(line)
            self.command.set('')
        return 'break'

    def send_command(self, command, program_input=True, log=True):
        process = self.process
        if process is None or process.poll() is not None:
            self.status.set('O processo GDB não está ativo.')
            return
        command = str(command).replace('\r', '').replace('\n', ' ').strip()
        if not command or len(command) > 4000:
            return
        if log:
            self.commands.append(command)
            if program_input and command not in ('run', 'continue', 'c', 'quit', 'q'):
                self.last_program_input = command
            if self.pty_fd is None:
                self.append(f'(gdb) {command}\n')
        try:
            payload = (command + '\n').encode('utf-8')
            if self.pty_fd is not None:
                os.write(self.pty_fd, payload)
            else:
                process.stdin.write(payload.decode('utf-8'))
                process.stdin.flush()
            if command.lower() in ('run', 'r'):
                self.status.set('Executando dentro do GDB. A entrada digitada vai para o programa enquanto ele estiver no prompt.')
        except (OSError, BrokenPipeError, ValueError) as exc:
            self.status.set(f'Falha ao enviar ao GDB: {exc}')

    def inspect_compare(self):
        self.capture_arguments = True
        self.string_results.clear()
        self.send_command('x/s $rdi', program_input=False, log=False)
        self.send_command('x/s $rsi', program_input=False, log=False)
        self.status.set('Inspecionando os argumentos de strcmp no breakpoint atual.')

    def on_output(self, text):
        self.append(text)
        if '[CTF] Argumentos de strcmp:' in text:
            self.capture_arguments = True
            self.string_results.clear()
            self.gdb_parse_buffer = ''
        if self.capture_arguments:
            self.gdb_parse_buffer = (self.gdb_parse_buffer + text)[-8000:]
            pattern = re.compile(r'(?:\$\d+\s*=\s*)?0x[0-9a-fA-F]+(?::|\s+)\s*"((?:\\.|[^"\\])*)"')
            self.string_results = pattern.findall(self.gdb_parse_buffer)
            if len(self.string_results) >= 2:
                decoded = [value.replace('\\"', '"').replace('\\\\', '\\')
                           for value in self.string_results[-2:]]
                candidate = next((value for value in decoded if value != self.last_program_input), '')
                if candidate:
                    self.candidate.set('Chave candidata: ' + candidate)
                    self.append('\nCHAVE CANDIDATA · ' + candidate + '\n', 'key')
                    self.status.set('GDB parou em strcmp. A candidata foi destacada; use Continuar para ver a resposta do desafio.')
                    self.capture_arguments = False

    def interrupt(self):
        if self.process is None or self.process.poll() is not None:
            return
        try:
            if self.pty_fd is not None:
                os.write(self.pty_fd, b'\x03')
            else:
                self.process.send_signal(signal.SIGINT)
            self.status.set('Interrupção enviada ao GDB/programa.')
        except OSError as exc:
            self.status.set(f'Não foi possível interromper: {exc}')

    def get_context(self):
        return ('Terminal GDB para '+str(self.binary)+'\n'
                'Chave apresentada: '+self.candidate.get()+'\n'
                'Comandos enviados: '+'; '.join(self.commands[-30:])+'\n'
                'Saída recente:\n'+self.output.get('1.0', 'end-1c')[-12000:])

    def poll(self):
        if self.closed:
            return
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'text':
                    self.on_output(value)
                else:
                    self.status.set('GDB encerrou.')
        except queue.Empty:
            pass
        self.after(80, self.poll)

    def stop_process(self):
        self.closed = True
        process = self.process
        if process is not None and process.poll() is None:
            try:
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            except OSError:
                pass
        if self.pty_fd is not None:
            try:
                os.close(self.pty_fd)
            except OSError:
                pass
            self.pty_fd = None

    def on_destroy(self, event):
        if event.widget is self:
            self.stop_process()

    def close(self):
        self.stop_process()
        self.destroy()
