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
from terminal_view import ANSI_STYLE, configure_terminal, insert_terminal
from system_install import package_install_command
from ctf_examples import CtfExamples
from ctf_theme import configure_ctf_styles
from ctf_help import HoverTip, john_terminal, show_document

LOADED_FORMAT = re.compile(r'^Loaded \d+ password hash(?:es)?(?: with .*?)? \(([^, )]+)', re.IGNORECASE)
FORMAT_ERROR = re.compile(r'^(?:No password hashes loaded|Unknown ciphertext format)', re.IGNORECASE)
ALTERNATE_FORMAT = re.compile(r'\balso recognized as\s+["\']?([\w-]+)', re.IGNORECASE)
NO_MATCHES = re.compile(r'^0 password hash(?:es)? cracked\b', re.IGNORECASE)
FORMAT_GUIDANCE = ('Confira se o hash está completo. Se você souber o algoritmo de origem, '
                   'informe o nome aceito pelo John no campo Formato e tente novamente. '
                   'Se esta versão do John não oferecer esse formato, use uma ferramenta compatível.')
HEX_LENGTHS = {'raw-md4': 32, 'raw-md5': 32, 'nt': 32, 'raw-sha1': 40,
               'raw-sha224': 56, 'raw-sha256': 64, 'raw-sha384': 96, 'raw-sha512': 128}
CRYPT_LENGTHS = {'1': ('md5crypt', 22), '5': ('sha256crypt', 43), '6': ('sha512crypt', 86)}
HEX_DIGIT = re.compile(r'[0-9a-fA-F]')
CRYPT_DIGIT = re.compile(r'[./0-9A-Za-z]')


def pasted_hash_value(text):
    account, separator, value = text.partition(':')
    if separator and re.fullmatch(r'[\w.@\\-]+', account) and not re.fullmatch(r'[0-9a-fA-F]{16,}', account):
        return value
    return text


def check_hash_length(value, offset, length, alphabet, label, component):
    for index, character in enumerate(value[:length]):
        if not alphabet.fullmatch(character):
            return f'{label}: caractere inválido {character!r} na posição {offset+index+1} do hash.'
    if len(value) > length:
        extra = len(value) - length
        return (f'{label}: {extra} caractere(s) a mais a partir da posição {offset+length+1} do hash. '
                f'Primeiro excedente: {value[length]!r}.')
    if len(value) < length:
        return f'{label}: faltam {length-len(value)} caractere(s). {component} deve ter {length}.'
    return ''


def pasted_hash_problem(text, format_name):
    value = pasted_hash_value(text)
    if re.match(r'^\$2[abxy]?\$', value):
        cost = re.match(r'^\$2[abxy]?\$[0-9]{2}\$', value)
        if not cost:
            return 'bcrypt: o custo após o prefixo deve ter dois dígitos e terminar em $.'
        offset = cost.end()
        return check_hash_length(value[offset:], offset, 53, CRYPT_DIGIT, 'bcrypt', 'O bloco de sal e resumo')
    prefix = re.match(r'^\$([156])\$', value)
    if prefix:
        label, length = CRYPT_LENGTHS[prefix[1]]
        salt = prefix.end()
        if prefix[1] in ('5', '6') and value.startswith('rounds=', salt):
            rounds = re.match(r'rounds=[0-9]+\$', value[salt:])
            if not rounds:
                return f'{label}: informe o número de iterações seguido de $ após rounds=.'
            salt += rounds.end()
        end = value.find('$', salt)
        if end < 0:
            return f'{label}: falta o separador $ entre o sal e o resumo.'
        salt_limit = 8 if prefix[1] == '1' else 16
        if end - salt > salt_limit:
            position = salt + salt_limit
            return (f'{label}: o sal tem {end-position} caractere(s) a mais a partir da posição '
                    f'{position+1} do hash. Primeiro excedente: {value[position]!r}.')
        offset = end + 1
        return check_hash_length(value[offset:], offset, length, CRYPT_DIGIT, label, 'O resumo')
    label = format_name.strip().lower()
    if label in HEX_LENGTHS and not value.startswith('$'):
        return check_hash_length(value, 0, HEX_LENGTHS[label], HEX_DIGIT, label, 'O hash hexadecimal')
    return ''


def raw_hash_hint(text):
    value = pasted_hash_value(text)
    prefix = re.match(r'[0-9A-Fa-f]+', value)
    if prefix is None:
        return ''
    lengths = HEX_LENGTHS.values()
    if prefix.end() in lengths and prefix.end() < len(value):
        length = prefix.end()
    else:
        length = max((size for size in lengths
                      if size <= prefix.end() and 0 < len(value)-size <= 3), default=0)
    if not length:
        return ''
    return (f'Se a origem usa um hash hexadecimal de {length} caracteres, '
            f'confira {len(value)-length} possível(is) caractere(s) a mais a partir da posição {length+1}. '
            f'Primeiro possível excedente: {value[length]!r}.')


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


def run_process(args, stop, events, show=False):
    """Drain output separately so cancellation also works when John is silent."""
    proc = None
    returncode = None
    try:
        options = {'start_new_session': True} if os.name != 'nt' else {
            'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                errors='replace', **options)

        def read():
            for line in proc.stdout:
                line = ANSI_STYLE.sub('', line)
                # John --show emits recovered entries as account:password[:fields].
                account, separator, _ = line.partition(':')
                recovered = show and separator and account and not any(c.isspace() for c in account)
                events.put(('recovered' if recovered else 'log', line))
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
        returncode = None if stop.is_set() else proc.returncode
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
        events.put(('done', returncode))


class JohnWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        configure_ctf_styles(self)
        self.examples = CtfExamples()
        self.title('John the Ripper · auditoria local de hashes')
        self.geometry('800x580'); self.minsize(620,440)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.showing = False
        self.loaded_format = ''
        self.alternate_formats = set()
        self.format_error = False
        self.no_matches = False
        self.last_hash_hint = ''
        self.installing = False
        self.directory = None
        self.inputs = None
        self.executable = tk.StringVar(value=shutil.which('john') or shutil.which('john.exe') or '')
        self.hashes = tk.StringVar(); self.wordlist = tk.StringVar()
        self.pasted_hash = tk.StringVar()
        self.format_name = tk.StringVar()
        frame = ttk.Frame(self, padding=14); frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1); frame.rowconfigure(8, weight=1)
        ttk.Label(frame, text='Cole um hash ou selecione um arquivo de hashes. Selecione a lista de palavras e clique em Iniciar.', wraplength=600).grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(0,8))
        self.fields = []
        for row, label, variable in ((1,'Executável John',self.executable),
                                     (2,'Arquivo de hashes',self.hashes),
                                     (4,'Lista de palavras',self.wordlist)):
            ttk.Label(frame,text=label).grid(row=row,column=0,sticky='w',padx=(0,8))
            entry = ttk.Entry(frame,textvariable=variable)
            entry.grid(row=row,column=1,sticky='ew',pady=4)
            button = ttk.Button(frame,text='Selecionar…',style='CtfInfo.TButton',command=lambda v=variable:self.browse(v))
            button.grid(row=row,column=2,padx=(8,0))
            self.fields.extend((entry,button))
        ttk.Label(frame,text='Colar hash').grid(row=3,column=0,sticky='w')
        pasted = ttk.Entry(frame,textvariable=self.pasted_hash)
        pasted.grid(row=3,column=1,sticky='ew',pady=4)
        self.fields.append(pasted)
        ttk.Label(frame,text='Formato (opcional)').grid(row=5,column=0,sticky='w')
        entry = ttk.Entry(frame,textvariable=self.format_name)
        entry.grid(row=5,column=1,sticky='ew',pady=4); self.fields.append(entry)
        ttk.Label(frame,text='Vazio = detecção automática. No Kali: sudo apt install john').grid(
            row=6,column=0,columnspan=3,sticky='w',pady=6)
        bar = ttk.Frame(frame); bar.grid(row=7,column=0,columnspan=3,sticky='ew',pady=6)
        self.start_button = ttk.Button(bar,text='Iniciar',style='CtfRun.TButton',command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(bar,text='Parar',style='CtfStop.TButton',command=self.stop,state='disabled')
        self.stop_button.pack(side='left',padx=6)
        self.show_button = ttk.Button(bar,text='Mostrar recuperadas',style='CtfInfo.TButton',command=lambda:self.start(show=True),state='disabled')
        self.show_button.pack(side='left')
        example = ttk.Button(bar,text='Carregar exemplo',style='CtfExample.TButton',command=self.load_example)
        example.pack(side='left',padx=6)
        clear = ttk.Button(bar,text='Limpar exemplo',style='CtfInfo.TButton',command=self.clear_example)
        clear.pack(side='left')
        self.fields.extend((example,clear))
        self.output = ScrolledText(frame,wrap='word',state='disabled')
        configure_terminal(self.output)
        self.output.grid(row=8,column=0,columnspan=3,sticky='nsew',pady=(8,0))
        self.status = tk.StringVar(value='Pronto' if self.executable.get() else 'John não encontrado: instale ou selecione o executável.')
        ttk.Label(frame,textvariable=self.status,wraplength=700).grid(row=9,column=0,columnspan=3,sticky='w',pady=(8,0))
        extra = ttk.Frame(frame)
        extra.grid(row=10,column=0,columnspan=3,sticky='ew',pady=6)
        help_button = ttk.Button(extra,text='Como usar no CTF',style='CtfExample.TButton',command=self.show_help)
        help_button.pack(side='left')
        code_button = ttk.Button(extra,text='Ver comando / código',style='CtfRun.TButton',command=self.show_code)
        code_button.pack(side='left',padx=8)
        HoverTip(help_button,'John the Ripper: guia para recuperar a senha a partir de um hash.')
        HoverTip(code_button,'Mostra os comandos john para testar a lista e consultar senhas recuperadas no terminal.')
        HoverTip(self.start_button,'John the Ripper compara as candidatas da lista com o hash local.')
        HoverTip(self.show_button,'John --show consulta o resultado salvo da última execução desta janela.')
        HoverTip(example,'Preenche Colar hash e deixa o John detectar o formato SHA-512 crypt.')
        HoverTip(clear,'Esvazia os campos de treino e a saída sem fechar a janela.')
        self.protocol('WM_DELETE_WINDOW',self.close)
        self.bind('<Destroy>',self.on_destroy,add='+')
        self.poll_id = self.after(100,self.poll)

    def show_help(self):
        return show_document(self,'John no CTF','Ferramenta: John the Ripper, para hashes locais.',
            '1. Clique em Carregar exemplo para preencher Colar hash e selecionar uma lista de quatro palavras.\n'
            '2. Para testar seu próprio hash, cole-o ou selecione um arquivo. Selecione uma lista com uma candidata por linha.\n'
            '3. Deixe Formato em branco para detecção automática. O exemplo começa com $6$, de SHA-512 crypt.\n'
            '4. Clique em Iniciar. Se o John precisar ser instalado, conclua a instalação e clique novamente.\n'
            '5. Aguarde o resultado em destaque. A senha do exemplo é caderno42.\n'
            '6. No site do CTF, envie CTF{caderno42}. Para outra missão, use a senha encontrada no lugar desse texto.\n'
            '7. Você também pode criar candidatas no Gerador de listas e selecionar o TXT aqui. Ver comando / código permite usar o John pelo terminal.')

    def show_code(self):
        return show_document(self,'John no terminal',
            'Execute a primeira linha para testar as palavras. Ao terminar, execute a segunda para mostrar as recuperadas. '
            'O resultado do terminal é salvo em ctf-terminal.pot na pasta atual. Substitua HASHES.txt e PALAVRAS.txt se estiverem como modelo.',
            john_terminal('' if self.pasted_hash.get().strip() else self.hashes.get(),
                          self.wordlist.get(),self.format_name.get()))

    def load_example(self):
        if self.running:
            return
        try:
            files = self.examples.files()
            example_hash = (files/'hashes.txt').read_text(encoding='utf-8').strip()
            self.pasted_hash.set(example_hash.partition(':')[2])
            self.hashes.set('')
            self.wordlist.set(str(files/'palavras.txt'))
            self.format_name.set('')
            self.inputs = None
            self.show_button.configure(state='disabled')
            self.output.configure(state='normal')
            self.output.delete('1.0','end')
            self.output.configure(state='disabled')
            self.append('1. O hash do exemplo já está em Colar hash. Formato está vazio para testar a detecção automática.\n'
                        '2. Clique em Iniciar. Se o John estiver ausente, instale quando solicitado e clique em Iniciar novamente.\n'
                        '3. Aguarde o formato detectado e o resultado em destaque. A senha é caderno42.\n'
                        '4. No CTF, a flag é CTF{caderno42}. Use Limpar exemplo para esvaziar os campos.\n')
            self.status.set('Exemplo carregado. Clique em Iniciar.')
        except OSError as exc:
            messagebox.showerror('Exemplo John',str(exc),parent=self)

    def clear_example(self):
        if self.running:
            return
        self.hashes.set(''); self.pasted_hash.set(''); self.wordlist.set(''); self.format_name.set('')
        self.inputs = None
        self.show_button.configure(state='disabled')
        self.output.configure(state='normal'); self.output.delete('1.0','end'); self.output.configure(state='disabled')
        self.status.set('Campos limpos. Você pode carregar o exemplo novamente.')

    def browse(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:
            variable.set(path)
            if variable is self.hashes:
                self.pasted_hash.set('')

    def append(self, text, tag=()):
        self.output.configure(state='normal'); insert_terminal(self.output, text, tag)
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
                    args = package_install_command(self, 'John the Ripper', 'john')
                    if not args:
                        return
                    self.installing = True
                    self.running = True
                    self.stop_event.clear()
                    for field in self.fields:
                        field.configure(state='disabled')
                    self.start_button.configure(state='disabled')
                    self.show_button.configure(state='disabled')
                    self.stop_button.configure(state='normal')
                    self.status.set('Aguardando autenticação e instalação do John…')
                    self.append('\nJohn não está instalado. Solicitando autorização do sistema…\n')
                    threading.Thread(target=run_process,args=(args,self.stop_event,self.events),daemon=True).start()
                    return
                hashes, wordlist, format_name = self.hashes.get(), self.wordlist.get(), self.format_name.get()
                directory = Path.home()/'.config'/'cyberpm'/'john-results'/uuid.uuid4().hex
            pasted_text = '' if show else self.pasted_hash.get()
            pasted_hash = pasted_text.strip()
            if pasted_hash:
                ignored = len(pasted_text) - len(pasted_hash)
                if ignored:
                    self.append(f'\nIgnorando {ignored} caractere(s) de espaço em branco nas extremidades do hash colado.\n',
                                'warning')
                if any(character in pasted_hash for character in '\r\n\0'):
                    raise ValueError('Cole um hash por vez em Colar hash. Para várias linhas, selecione um arquivo.')
                if problem := pasted_hash_problem(pasted_hash, format_name):
                    self.status.set('O hash colado tem um problema de estrutura.')
                    self.append('\n'+problem+'\n', 'error')
                    return
                directory.mkdir(parents=True,mode=0o700)
                hashes = directory/'hashes.txt'
                try:
                    hashes.write_text(pasted_hash+'\n',encoding='utf-8')
                    args = command(executable,hashes,wordlist,format_name,directory)
                except (ValueError,OSError,TypeError):
                    hashes.unlink(missing_ok=True)
                    directory.rmdir()
                    raise
            else:
                args = command(executable,hashes,wordlist,format_name,directory,show)
                directory.mkdir(parents=True,mode=0o700,exist_ok=True)
        except (ValueError,OSError,TypeError) as exc:
            messagebox.showerror('John the Ripper',str(exc),parent=self); return
        self.directory = directory
        self.inputs = (executable,str(Path(hashes).expanduser().resolve()),wordlist,format_name)
        self.showing = show
        if not show:
            self.loaded_format = ''
            self.alternate_formats.clear()
            self.last_hash_hint = raw_hash_hint(pasted_hash) if not format_name.strip() else ''
        self.format_error = False
        self.no_matches = False
        self.running = True; self.stop_event.clear()
        for field in self.fields:
            field.configure(state='disabled')
        self.start_button.configure(state='disabled'); self.show_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Executando — resultados locais: '+str(directory))
        if show:
            self.append('\nSenhas recuperadas\n', 'result')
        else:
            self.append('\nIniciando auditoria por lista de palavras…\n')
        threading.Thread(target=run_process,args=(args,self.stop_event,self.events,show),daemon=True).start()

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
                if not self.installing:
                    self.read_result_status(value)
            elif kind == 'recovered':
                self.append(value, 'result')
            else:
                self.running = False
                for field in self.fields:
                    field.configure(state='normal')
                self.start_button.configure(state='normal')
                self.show_button.configure(state='normal' if self.inputs else 'disabled')
                self.stop_button.configure(state='disabled')
                if self.installing:
                    self.installing = False
                    executable = shutil.which('john') or shutil.which('john.exe')
                    if value == 0 and executable:
                        self.executable.set(executable)
                        self.status.set('John instalado. Selecione os hashes e a wordlist para começar.')
                        self.append('\nJohn instalado com sucesso.\n')
                    else:
                        self.status.set('A instalação do John não foi concluída.')
                elif self.format_error:
                    self.status.set('O John não conseguiu carregar o hash com o formato atual.')
                    if self.last_hash_hint:
                        self.append('\n'+self.last_hash_hint+'\n', 'warning')
                    self.append('\n'+FORMAT_GUIDANCE+'\n', 'warning')
                elif value == 0 and not self.showing:
                    if self.alternate_formats and not self.inputs[3].strip():
                        alternatives = ', '.join(sorted(self.alternate_formats))
                        self.append(f'\nFormato ambíguo. O John também reconheceu: {alternatives}. '
                                    'Se você souber o algoritmo de origem, informe-o em Formato.\n', 'warning')
                    self.start(show=True)
                elif value == 0 and self.no_matches:
                    self.status.set('Nenhuma senha da lista foi recuperada.')
                    if self.loaded_format:
                        self.append(f'\nFormato usado: {self.loaded_format}. Se for diferente do algoritmo de origem, '
                                    'selecione o formato correto. Se estiver certo, confira a lista de palavras.\n', 'warning')
                elif value == 0:
                    self.status.set('Resultado exibido — arquivos locais: '+str(self.directory))
                elif self.stop_event.is_set():
                    self.status.set('Execução interrompida. Use Mostrar recuperadas para consultar resultados parciais.')
                else:
                    self.status.set('O John encerrou com erro. Confira a mensagem na saída.')
        self.poll_id = self.after(100,self.poll)

    def read_result_status(self, line):
        if match := LOADED_FORMAT.match(line):
            self.loaded_format = match[1]
            label = 'Formato usado' if self.inputs[3].strip() else 'Formato detectado'
            self.append(f'{label} pelo John: {self.loaded_format}. Hash carregado.\n', 'info')
        elif match := ALTERNATE_FORMAT.search(line):
            self.alternate_formats.add(match[1])
        elif FORMAT_ERROR.match(line):
            self.format_error = True
        elif self.showing and NO_MATCHES.match(line):
            self.no_matches = True

    def on_destroy(self, event):
        if event.widget is self:
            self.after_cancel(self.poll_id)
            self.stop_event.set()
            self.examples.close()

    def close(self):
        self.stop(); self.destroy()
