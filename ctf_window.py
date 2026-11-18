"""CTF workstation for local evidence and explicit tool runs."""
import binascii
from pathlib import Path
import queue
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import webbrowser

from ctf_tools import (capture_command, file_report, host_name, local_file,
                       log_report, port_range, target_url, transform, web_command)
from sherlock_window import run_process
from system_install import package_install_command


class CtfWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('CTF · ferramentas e estudo')
        self.geometry('1030x800')
        self.minsize(760, 620)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.busy = False
        self.buttons = []
        self.status = tk.StringVar(value='Escolha uma aba. A saída aparece na parte inferior.')
        main = ttk.Frame(self, padding=12)
        main.pack(fill='both', expand=True)
        notebook = ttk.Notebook(main)
        notebook.pack(fill='x')
        for title, builder in [('Capturas', self.capture_tab), ('Codificação', self.decode_tab),
                               ('Arquivos', self.file_tab), ('Logs', self.logs_tab),
                               ('Portas', self.ports_tab), ('Web e sessão', self.web_tab),
                               ('Guia e listas', self.guide_tab)]:
            tab = ttk.Frame(notebook, padding=10)
            notebook.add(tab, text=title)
            builder(tab)
        bar = ttk.Frame(main)
        bar.pack(fill='x', pady=8)
        self.stop_button = ttk.Button(bar, text='Parar processo', command=self.stop_event.set,
                                      state='disabled')
        self.stop_button.pack(side='left')
        ttk.Button(bar, text='Salvar saída…', command=self.save).pack(side='left', padx=8)
        ttk.Label(bar, textvariable=self.status, wraplength=650).pack(side='left')
        self.output = ScrolledText(main, wrap='word', state='disabled', height=18)
        self.output.pack(fill='both', expand=True)
        self.poll_id = self.after(100, self.poll)
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.bind('<Destroy>', self.on_destroy, add='+')

    def note(self, frame, text):
        ttk.Label(frame, text=text, wraplength=920, justify='left').pack(anchor='w', pady=(0, 8))

    def field(self, frame, label, default='', browse=False, choices=None):
        row = ttk.Frame(frame)
        row.pack(fill='x', pady=3)
        ttk.Label(row, text=label, width=23).pack(side='left')
        variable = tk.StringVar(value=default)
        if choices:
            widget = ttk.Combobox(row, textvariable=variable, values=choices, state='readonly')
        else:
            widget = ttk.Entry(row, textvariable=variable)
        widget.pack(side='left', fill='x', expand=True)
        if browse:
            ttk.Button(row, text='Selecionar…', command=lambda: self.browse(variable)).pack(side='left', padx=6)
        return variable

    def browse(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:
            variable.set(path)

    def action(self, frame, text, callback):
        button = ttk.Button(frame, text=text, command=callback)
        button.pack(side='left', padx=(0, 8), pady=7)
        self.buttons.append(button)

    def capture_tab(self, frame):
        self.note(frame, 'Abra um PCAP/PCAPNG. DNS mostra nomes consultados. Conversa TCP junta os dados de um fluxo. '
                  'No resumo, o filtro de exibição limita os pacotes mostrados. Comece com dns ou http.')
        self.capture = self.field(frame, 'Arquivo de captura', browse=True)
        self.capture_mode = self.field(frame, 'Operação', 'Consultas DNS', choices=[
            'Consultas DNS', 'Conversa TCP', 'Resumo filtrado'])
        self.display_filter = self.field(frame, 'Filtro de exibição', 'http')
        self.stream = self.field(frame, 'Índice da conversa TCP', '0')
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Ler com TShark', lambda: self.external(lambda: capture_command(
            self.capture.get(), self.capture_mode.get(), self.display_filter.get(), self.stream.get())))
        self.action(bar, 'Abrir no Wireshark', lambda: self.external(
            lambda: ['wireshark', '-r', local_file(self.capture.get())]))

    def decode_tab(self, frame):
        self.note(frame, 'Cole a evidência. Base64 pode terminar em =. Para XOR, use os bytes em hexadecimal '
                  'e uma chave hexadecimal de um byte, como 2a. O resultado é texto UTF-8 ou bytes em hexadecimal.')
        self.operation = self.field(frame, 'Operação', 'Base64 → texto', choices=[
            'Base64 → texto', 'Texto → Base64', 'Hexadecimal → texto', 'Texto → hexadecimal', 'XOR de um byte'])
        self.key = self.field(frame, 'Chave XOR hexadecimal', '2a')
        self.input_text = ScrolledText(frame, height=4, wrap='word')
        self.input_text.pack(fill='x', pady=5)
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Converter', self.decode)

    def decode(self):
        text, operation, key = self.input_text.get('1.0', 'end-1c'), self.operation.get(), self.key.get()
        if len(text) > 2_000_000:
            return messagebox.showerror('Entrada grande', 'Use até 2 MB de texto.', parent=self)
        self.local(lambda: transform(text, operation, key))

    def file_tab(self, frame):
        self.note(frame, 'Identifique assinatura, SHA-256 e texto escondido no arquivo. '
                  'O resumo lê até 2 MB para strings e calcula o hash de todo o arquivo. '
                  'ExifTool mostra os campos de metadados, incluindo comentários PNG quando presentes.')
        self.file = self.field(frame, 'Arquivo', browse=True)
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Assinatura, hash e strings', self.inspect_file)
        self.action(bar, 'Metadados ExifTool', lambda: self.external(
            lambda: ['exiftool', '-G1', '-a', '-s', local_file(self.file.get())]))

    def inspect_file(self):
        path = self.file.get()
        self.local(lambda: file_report(path))

    def logs_tab(self, frame):
        self.note(frame, 'Carregue um log e filtre por texto, como user=aluno. O agrupamento reconhece '
                  'ip=, user= e os eventos FAIL/OK. Compare cada sequência com a regra da missão. '
                  'Outros formatos continuam visíveis na lista de linhas.')
        self.log = self.field(frame, 'Arquivo de log', browse=True)
        self.query = self.field(frame, 'Texto a procurar')
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Filtrar e agrupar', self.inspect_log)

    def inspect_log(self):
        path, query = self.log.get(), self.query.get()
        self.local(lambda: log_report(path, query))

    def ports_tab(self, frame):
        self.note(frame, 'Informe o IP/host do laboratório e as portas. O Nmap testa conexões TCP. '
                  'Na saída, open indica porta que aceita conexão. Para o serviço do CTF, inicie '
                  'python3 servico.py no mesmo Kali antes de usar 127.0.0.1.')
        self.host = self.field(frame, 'Host ou IP', '127.0.0.1')
        self.ports = self.field(frame, 'Portas ou intervalo', '8780-8789')
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Executar Nmap', self.scan_ports)

    def scan_ports(self):
        def command():
            host = host_name(self.host.get())
            return ['nmap'] + (['-6'] if ':' in host else []) + [
                '-sT', '-Pn', '-p', port_range(self.ports.get()), host]
        self.external(command)

    def web_tab(self, frame):
        self.note(frame, 'Use a URL completa do exercício, incluindo ?q=Redes para SQL ou ?q=teste para XSS. '
                  'Resposta e cabeçalhos permite comparar acessos antes/depois de um cookie. '
                  'Os scanners precisam de revisão manual dos resultados e podem demorar. Use o alvo do laboratório.')
        self.url = self.field(frame, 'URL', 'http://127.0.0.1:8765/')
        self.cookie = self.field(frame, 'Cookie opcional', '')
        self.web_mode = self.field(frame, 'Operação', 'Resposta e cabeçalhos', choices=[
            'Resposta e cabeçalhos', 'SQLmap', 'Dalfox (XSS)'])
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Executar', lambda: self.external(lambda: web_command(
            self.web_mode.get(), self.url.get(), self.cookie.get())))
        self.action(bar, 'Abrir no navegador', self.open_browser)
        self.note(frame, 'Para aluno → admin, consulte /admin sem cookie e depois com papel=admin. '
                  'Observe o status e o corpo nas duas saídas. Para provar execução de XSS, abra o formulário '
                  'no navegador e siga a missão. O curl exibe HTML como texto.')

    def open_browser(self):
        try:
            webbrowser.open(target_url(self.url.get()))
        except ValueError as exc:
            messagebox.showerror('URL inválida', str(exc), parent=self)

    def guide_tab(self, frame):
        self.note(frame, '1. Leia o objetivo e escolha a aba pela evidência.\n'
                  '2. Selecione o arquivo ou endereço e execute. A saída aparece abaixo.\n'
                  '3. Leia os campos, monte CTF{resposta} e envie no CTF Lab.\n\n'
                  'Hydra e John continuam nos próprios botões do Cyberpm. Abra as capturas com TShark/Wireshark; '
                  'use Codificação para Base64/XOR e Arquivos para assinaturas/comentários. '
                  'Logs e OWASP exigem comparar a evidência com a regra descrita na missão.')
        self.package = self.field(frame, 'Pacote do Kali', 'tshark', choices=[
            'tshark', 'wireshark', 'nmap', 'curl', 'sqlmap', 'dalfox', 'seclists', 'libimage-exiftool-perl'])
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Instalar pacote escolhido', self.install)
        self.action(bar, 'Abrir histórias e guias', lambda: webbrowser.open(
            'https://ctf-lab-estudos-mwkq0dq4.hushedcrab131.chatgpt.site/#guias'))
        self.note(frame, 'SecLists fica em /usr/share/seclists após a instalação. Escolha Passwords para senhas '
                  'e Discovery/Web-Content para caminhos web. Nos exercícios de Hydra e John, selecione primeiro '
                  'as pequenas listas do ZIP. Para inspecionar uma lista, use Arquivos. '
                  'Se um pacote não estiver disponível no seu Kali, consulte o erro retornado pelo apt.')

    def install(self):
        if self.busy:
            return
        package = self.package.get()
        args = package_install_command(self, package, package)
        if args:
            self.launch(args)

    def external(self, builder):
        if self.busy:
            return
        try:
            args = builder()
            executable = shutil.which(args[0])
            if not executable:
                package = {'exiftool': 'libimage-exiftool-perl'}.get(args[0], args[0])
                raise ValueError(f'{args[0]} ausente. Na aba Guia e listas, instale {package}.')
            args[0] = executable
            self.launch(args)
        except (ValueError, OSError) as exc:
            messagebox.showerror('Confira os campos', str(exc), parent=self)

    def launch(self, args):
        self.begin()
        # Cookies can contain session secrets, so commands are not echoed.
        threading.Thread(target=run_process, args=(args, self.stop_event, self.events, 'CTF'), daemon=True).start()

    def local(self, callback):
        if self.busy:
            return
        self.begin()
        self.stop_button.configure(state='disabled')
        def worker():
            try:
                self.events.put(('log', callback()))
                self.events.put(('done', 0))
            except (ValueError, OSError, binascii.Error) as exc:
                self.events.put(('log', f'Não foi possível processar: {exc}'))
                self.events.put(('done', 1))
        threading.Thread(target=worker, daemon=True).start()

    def begin(self):
        self.busy = True
        self.stop_event.clear()
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        for button in self.buttons:
            button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Executando…')

    def poll(self):
        for _ in range(200):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'log':
                self.output.configure(state='normal')
                self.output.insert('end', value)
                # Bound the visible output without blocking process drainage.
                if int(self.output.index('end-1c').split('.')[0]) > 12000:
                    self.output.delete('1.0', '2001.0')
                self.output.see('end')
                self.output.configure(state='disabled')
            elif kind == 'done':
                self.busy = False
                for button in self.buttons:
                    button.configure(state='normal')
                self.stop_button.configure(state='disabled')
                self.status.set('Interrompido.' if self.stop_event.is_set() else
                                'Concluído.' if value == 0 else f'Falha ou resultado parcial (código {value}). Leia a saída.')
        self.poll_id = self.after(100, self.poll)

    def save(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.txt')
        if path:
            try:
                Path(path).write_text(self.output.get('1.0', 'end-1c'), encoding='utf-8')
            except OSError as exc:
                messagebox.showerror('Falha ao salvar', str(exc), parent=self)

    def on_destroy(self, event):
        if event.widget is self:
            self.stop_event.set()

    def close(self):
        self.stop_event.set()
        self.after_cancel(self.poll_id)
        self.destroy()
