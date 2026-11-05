"""Separate Hydra launcher with streamed output and cancellation."""
import queue
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit
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


SERVICES = ('ssh', 'ftp', 'ftps', 'sftp', 'rdp', 'smb', 'mysql', 'postgres',
            'imap', 'imaps', 'pop3', 'pop3s', 'smtp', 'smtps',
            'http-get', 'https-get', 'http-post-form', 'https-post-form')


def form_command(executable, target, service, username, wordlist, port='', tasks='4',
                 delay='1', module='', stop_first=True):
    target, username = target.strip(), username.strip()
    if not target or target.startswith('-') or any(c.isspace() for c in target):
        raise ValueError('Informe um host ou IP, sem protocolo, caminho ou espacos.')
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if len(target) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                       for label in target.rstrip('.').split('.')):
            raise ValueError('Host ou IP invalido.')
    if service not in SERVICES or not username or '\n' in username or '\r' in username:
        raise ValueError('Selecione o servico e informe um usuario.')
    words = Path(wordlist).expanduser()
    if not wordlist or not words.is_file() or words.stat().st_size == 0:
        raise ValueError('Selecione uma wordlist existente e nao vazia.')
    try:
        count, pause = int(tasks), int(delay)
        number = int(port) if port.strip() else None
    except ValueError:
        raise ValueError('Porta, conexoes e intervalo devem ser numeros inteiros.')
    if not 1 <= count <= 64 or not 0 <= pause <= 3600 or (number is not None and not 1 <= number <= 65535):
        raise ValueError('Use 1 a 64 conexoes, intervalo de 0 a 3600 s e porta de 1 a 65535.')
    if service.endswith('post-form') and (not module.strip() or '^USER^' not in module or '^PASS^' not in module):
        raise ValueError('Formulario HTTP requer caminho, campos ^USER^ / ^PASS^ e condicao F= ou S= nas opcoes do servico.')
    if service.endswith('post-form') and not re.search(r'(?:^|:)[FS]=.', module):
        raise ValueError('Informe uma condicao F= ou S= para identificar o resultado do login.')
    args = build_command(executable, '')[:1]
    args += ['-l', username, '-P', str(words.resolve()), '-t', str(count), '-W', str(pause), '-v']
    if stop_first:
        args.append('-f')
    if number is not None:
        args += ['-s', str(number)]
    args += [target, service]
    if module.strip():
        args.append(module.strip())
    return args


def save_wordlist(path, text):
    lines = list(dict.fromkeys(line for line in text.splitlines() if line))
    if not lines:
        raise ValueError('Digite pelo menos uma senha, uma por linha.')
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return len(lines)


def download_command(url, destination):
    parsed = urlsplit(url.strip())
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Informe uma URL HTTP ou HTTPS direta para um arquivo de texto.')
    wget = shutil.which('wget')
    if not wget:
        raise ValueError('wget nao encontrado. No Kali: sudo apt install wget')
    return [wget, '--timeout=20', '--tries=2', '-O', str(destination), '--', url.strip()]


class HydraWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('Hydra · execução independente')
        self.geometry('1000x800')
        self.minsize(850, 700)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.executable = tk.StringVar(value=shutil.which('hydra') or '')
        self.target = tk.StringVar()
        self.service = tk.StringVar(value='ssh')
        self.username = tk.StringVar()
        self.wordlist = tk.StringVar()
        self.port = tk.StringVar()
        self.tasks = tk.StringVar(value='4')
        self.delay = tk.StringVar(value='1')
        self.module = tk.StringVar()
        self.url = tk.StringVar()
        self.stop_first = tk.BooleanVar(value=True)
        self.download_path = None
        self.download_temp = None
        self.controls = []
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
        rows = [
            ('Alvo (host ou IP)', self.target), ('Usuario', self.username),
            ('Wordlist de senhas', self.wordlist), ('Porta (vazio = padrao)', self.port),
            ('Conexoes paralelas (1-64)', self.tasks), ('Intervalo por conexao (segundos)', self.delay),
            ('Opcoes do servico / formulario', self.module), ('URL da wordlist (texto direto)', self.url)]
        for row, (label, variable) in enumerate(rows, start=2):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=(0, 8))
            entry = ttk.Entry(frame, textvariable=variable)
            entry.grid(row=row, column=1, sticky='ew', pady=3)
            self.controls.append(entry)
        for row, label, command in ((4, 'Selecionar...', self.browse_words),
                                     (9, 'Baixar com wget', self.download)):
            button = ttk.Button(frame, text=label, style='Accent.TButton' if row == 9 else 'Brute.TButton', command=command)
            button.grid(row=row, column=2, padx=(8, 0))
            self.controls.append(button)
        ttk.Label(frame, text='Servico').grid(row=10, column=0, sticky='w')
        self.service_box = ttk.Combobox(frame, textvariable=self.service, values=SERVICES, state='readonly')
        self.service_box.grid(row=10, column=1, sticky='ew', pady=3)
        create = ttk.Button(frame, text='Criar wordlist...', style='Brute.TButton', command=self.create_words)
        create.grid(row=10, column=2, padx=(8, 0))
        check = ttk.Checkbutton(frame, text='Parar ao encontrar uma senha valida', variable=self.stop_first)
        check.grid(row=11, column=0, columnspan=3, sticky='w')
        self.controls += [self.exe_entry, self.browse_button, create, check]
        ttk.Label(frame, text='Mais conexoes podem causar bloqueios ou erros. HTTP POST requer campos e condicao do formulario.',
                  wraplength=850).grid(row=12, column=0, columnspan=3, sticky='w', pady=4)
        bar = ttk.Frame(frame)
        bar.grid(row=13, column=0, columnspan=3, sticky='ew', pady=6)
        self.start_button = ttk.Button(bar, text='Iniciar teste', style='Start.TButton', command=self.start)
        self.start_button.pack(side='left')
        self.controls.append(self.start_button)
        self.stop_button = ttk.Button(bar, text='Parar', style='Stop.TButton', command=self.stop, state='disabled')
        self.stop_button.pack(side='left', padx=6)
        help_button = ttk.Button(bar, text='Ajuda do servico', command=self.help_service)
        help_button.pack(side='left')
        self.controls.append(help_button)
        self.output = ScrolledText(frame, wrap='word', state='disabled', height=10)
        self.output.grid(row=14, column=0, columnspan=3, sticky='nsew')
        frame.rowconfigure(14, weight=1)
        ttk.Label(frame, textvariable=self.status, wraplength=850).grid(
            row=15, column=0, columnspan=3, sticky='w', pady=(8, 0))
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

    def browse_words(self):
        path = filedialog.askopenfilename(parent=self, title='Selecione a wordlist de senhas')
        if path:
            self.wordlist.set(path)

    def create_words(self):
        editor = tk.Toplevel(self)
        editor.title('Criar wordlist - uma senha por linha')
        editor.geometry('560x420')
        text = ScrolledText(editor, wrap='none')
        text.pack(fill='both', expand=True, padx=10, pady=10)

        def save():
            if self.running:
                return
            path = filedialog.asksaveasfilename(parent=editor, defaultextension='.txt', title='Salvar wordlist')
            if not path:
                return
            try:
                count = save_wordlist(path, text.get('1.0', 'end-1c'))
            except (OSError, ValueError) as exc:
                messagebox.showerror('Wordlist', str(exc), parent=editor)
                return
            self.wordlist.set(path)
            self.status.set(f'Wordlist salva: {count} senhas sem duplicatas.')
            editor.title(f'Wordlist salva - {count} senhas')
        ttk.Button(editor, text='Salvar e selecionar', style='Start.TButton', command=save).pack(pady=(0, 10))

    def launch(self, args, tool='Hydra'):
        self.running = True
        self.stop_event.clear()
        for widget in self.controls:
            widget.configure(state='disabled')
        self.service_box.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set(tool + ' em execucao...')
        self.append('\nIniciando ' + tool + '...\n')
        threading.Thread(target=run_process, args=(args, self.stop_event, self.events, tool), daemon=True).start()

    def start(self):
        if self.running:
            return
        try:
            args = form_command(self.executable.get(), self.target.get(), self.service.get(),
                                self.username.get(), self.wordlist.get(), self.port.get(),
                                self.tasks.get(), self.delay.get(), self.module.get(), self.stop_first.get())
        except (OSError, ValueError) as exc:
            messagebox.showerror('Hydra', str(exc), parent=self)
            return
        self.launch(args)

    def help_service(self):
        if self.running:
            return
        try:
            args = build_command(self.executable.get(), '')[:1] + ['-U', self.service.get()]
        except ValueError as exc:
            messagebox.showerror('Hydra', str(exc), parent=self)
            return
        self.launch(args)

    def download(self):
        if self.running:
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.txt', title='Baixar wordlist para')
        if not path:
            return
        import tempfile
        try:
            # Keep an existing destination intact if download fails or is cancelled.
            args = download_command(self.url.get(), path)
            with tempfile.NamedTemporaryFile(dir=Path(path).parent, prefix='.cyberpm-', delete=False) as temp:
                partial = Path(temp.name)
            args[args.index('-O') + 1] = str(partial)
        except (OSError, ValueError) as exc:
            messagebox.showerror('Wordlist', str(exc), parent=self)
            return
        self.download_path, self.download_temp = Path(path), partial
        self.launch(args, 'wget')

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
                for widget in self.controls:
                    widget.configure(state='normal')
                self.service_box.configure(state='readonly')
                self.stop_button.configure(state='disabled')
                if self.download_temp is not None:
                    try:
                        if value == 0 and not self.stop_event.is_set() and self.download_temp.stat().st_size:
                            self.download_temp.replace(self.download_path)
                            self.wordlist.set(str(self.download_path))
                            self.append('Wordlist baixada e selecionada. Clique em Iniciar teste.\n')
                        elif value == 0 and not self.stop_event.is_set():
                            value = None
                            self.append('Download vazio; selecao anterior preservada.\n')
                    except OSError as exc:
                        value = None
                        self.append(f'Falha ao salvar wordlist: {exc}\n')
                    finally:
                        self.download_temp.unlink(missing_ok=True)
                        self.download_path = self.download_temp = None
                self.status.set('Interrompido' if self.stop_event.is_set() else
                                'Falha ao executar' if value is None else f'Encerrado (código {value})')
        self.poll_id = self.after(100, self.poll)

    def close(self):
        self.stop()
        if self.running:
            self.status.set('Aguardando processo encerrar para fechar...')
            self.after(100, self.close)
            return
        self.after_cancel(self.poll_id)
        self.destroy()
