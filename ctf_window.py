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

from ctf_tools import (capture_command, file_report, local_file,
                       log_report, target_url, transform, web_command,
                       generate_wordlist, save_wordlist, nmap_command, http_file_report, replace_query)
from ctf_help import (ACTION_TOOLS, TOOL_GUIDES, HoverTip, conversion_script, logs_script,
                      shell_command, show_document, wordlist_script)
from ctf_examples import CtfExamples
from ctf_importer import ctf_lab_challenge_url, import_ctf_lab_results, is_ctf_lab_url
from ctf_theme import configure_ctf_styles
from sherlock_window import run_process
from system_install import package_install_command


class CtfWindow(tk.Toplevel):
    def __init__(self, parent, tools=None):
        super().__init__(parent)
        configure_ctf_styles(self)
        self.examples = CtfExamples()
        self.tool_actions = tools or {}
        self.title('CTF · ferramentas e estudo')
        self.geometry('1060x860')
        self.minsize(780, 700)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.busy = False
        self.buttons = []
        self.status = tk.StringVar(value='Escolha uma aba. A saída aparece na parte inferior.')
        main = ttk.Frame(self, padding=12)
        main.pack(fill='both', expand=True)
        navigation = ttk.Frame(main)
        navigation.pack(fill='x', pady=(0, 5))
        navigation.columnconfigure(tuple(range(4)), weight=1)
        self.nav_buttons = {}
        self.tab_frames = {}
        self.tool_summary = tk.StringVar()
        ttk.Label(main, textvariable=self.tool_summary, wraplength=970).pack(anchor='w', pady=(0,8))
        ttk.Style(self).layout('Ctf.TNotebook.Tab', [])
        notebook = ttk.Notebook(main, style='Ctf.TNotebook')
        self.notebook = notebook
        notebook.pack(fill='x')
        for title, builder in [('Capturas', self.capture_tab), ('Codificação', self.decode_tab),
                               ('Arquivos', self.file_tab), ('Logs', self.logs_tab),
                               ('Portas', self.ports_tab), ('Web e sessão', self.web_tab),
                               ('Gerador de listas', self.wordlist_tab), ('Guia e listas', self.guide_tab)]:
            tab = ttk.Frame(notebook, padding=10)
            notebook.add(tab, text=title)
            builder(tab)
            index = len(self.nav_buttons)
            color = ['#60a5fa','#c4a7ff','#facc15','#5eead4','#4ade80','#fda4af','#fdba74','#a5b4fc'][index]
            button = tk.Button(navigation, text=title, background=color, foreground='#102031',
                               activebackground='#ffffff', activeforeground='#102031',
                               font=('TkDefaultFont',10,'bold'), relief='raised', borderwidth=2,
                               highlightthickness=2, highlightbackground=color, highlightcolor='#ffffff',
                               padx=8, pady=7, takefocus=True, command=lambda name=title:self.select_tab(name))
            button.grid(row=index//4,column=index%4,sticky='ew',padx=3,pady=3)
            HoverTip(button, TOOL_GUIDES[title][0])
            self.nav_buttons[title] = button
            self.tab_frames[title] = tab
        importer = tk.Button(navigation,text='Importar CTF externo · arquivo, URL ou pacote de laboratório',
                             background='#fbbf24',foreground='#102031',activebackground='#fde68a',
                             activeforeground='#102031',font=('TkDefaultFont',10,'bold'),padx=8,pady=7,
                             command=self.open_importer)
        importer.grid(row=2,column=0,columnspan=4,sticky='ew',padx=3,pady=3)
        HoverTip(importer,'Importação opcional de evidências, URLs e pacotes ZIP/pastas com README ou ctf.json.')
        self.notebook.bind('<<NotebookTabChanged>>',self.tab_changed)
        self.select_tab('Capturas')
        bar = ttk.Frame(main)
        bar.pack(fill='x', pady=8)
        self.stop_button = ttk.Button(bar, text='Parar processo', style='CtfStop.TButton', command=self.stop_event.set,
                                      state='disabled')
        self.stop_button.pack(side='left')
        HoverTip(self.stop_button, 'Interrompe o programa externo que este painel iniciou.')
        save = ttk.Button(bar, text='Salvar saída…', style='CtfInfo.TButton', command=self.save)
        save.pack(side='left',padx=8)
        HoverTip(save, 'Salva o texto visível em um arquivo de sua escolha.')
        help_button = ttk.Button(bar,text='Como usar no CTF',style='CtfExample.TButton',command=self.show_help)
        help_button.pack(side='left',padx=(0,8))
        HoverTip(help_button,'Abre um passo a passo para a ferramenta selecionada e sua missão.')
        code_button = ttk.Button(bar,text='Ver comando / código',style='CtfRun.TButton',command=self.show_code)
        code_button.pack(side='left')
        HoverTip(code_button,'Mostra e permite copiar o comando ou script com os campos atuais para usar no terminal do Kali.')
        ttk.Label(main, textvariable=self.status, wraplength=970).pack(anchor='w',pady=(0,6))
        self.output = ScrolledText(main, wrap='word', state='disabled', height=18)
        self.output.tag_configure('ctf-flag', foreground='#103d23', background='#baf3cb',
                                  font=('TkFixedFont', 13, 'bold'), spacing1=5, spacing3=5)
        self.output.pack(fill='both', expand=True)
        self.poll_id = self.after(100, self.poll)
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.bind('<Destroy>', self.on_destroy, add='+')

    def open_importer(self):
        from ctf_import_window import ImportCtfWindow
        window = getattr(self,'import_window',None)
        if window is not None and window.winfo_exists():
            window.lift()
            return window
        self.import_window = ImportCtfWindow(self,self.open_imported_file,self.use_imported_url)
        return self.import_window

    def open_imported_file(self, tool, path):
        if tool.startswith('John') or tool.startswith('Hydra'):
            name = 'John' if tool.startswith('John') else 'Hydra'
            callback = self.tool_actions.get(name)
            window = callback() if callback is not None else None
            if window is None:
                attribute = 'import_john' if name=='John' else 'import_hydra'
                window = getattr(self,attribute,None)
                if window is None or not window.winfo_exists():
                    if name=='John':
                        from john_window import JohnWindow
                        window = JohnWindow(self)
                    else:
                        from hydra_window import HydraWindow
                        window = HydraWindow(self)
                    setattr(self,attribute,window)
            if name=='Hydra' or 'wordlist' in tool:
                window.wordlist.set(path)
            else:
                window.hashes.set(path)
            window.lift()
            return
        title = tool if tool in ('Capturas','Logs') else 'Arquivos'
        self.select_tab(title)
        variable = {'Capturas':self.capture,'Logs':self.log,'Arquivos':self.file}[title]
        variable.set(path)
        self.explain('Arquivo externo preparado: '+path+'\n\nConfira as opções e execute a ferramenta quando estiver pronto. '
                     'Como usar no CTF e Ver comando / código continuam disponíveis.')
        self.lift()

    def use_imported_url(self, url):
        self.select_tab('Web e sessão')
        self.url.set(target_url(url))
        self.cookie.set('')
        self.parameter_value.set('')
        self.web_mode.set('Resposta e cabeçalhos')
        self.explain('URL externa preparada: '+url+'\n\nEscolha curl, SQLmap ou Dalfox e confira os campos antes de executar. '
                     'Use o navegador para as etapas interativas do laboratório.')
        self.lift()

    def select_tab(self, title):
        self.notebook.select(self.tab_frames[title])
        self.update_navigation(title)

    def tab_changed(self, event=None):
        selected = self.notebook.select()
        title = next((name for name,frame in self.tab_frames.items() if str(frame)==selected), 'Capturas')
        self.update_navigation(title)

    def update_navigation(self, title):
        self.current_tab = title
        self.tool_summary.set(TOOL_GUIDES[title][0])
        for name,button in self.nav_buttons.items():
            button.configure(relief='sunken' if name==title else 'raised',
                             highlightbackground='#ffffff' if name==title else button.cget('background'))

    def show_help(self):
        description, instructions = TOOL_GUIDES[self.current_tab]
        return show_document(self, 'Como usar no CTF · '+self.current_tab, description, instructions)

    def terminal_preview(self):
        title = self.current_tab
        description = TOOL_GUIDES[title][0]
        if title == 'Capturas':
            source = self.capture.get() or 'CAPTURA.pcap'
            args = capture_command(source,self.capture_mode.get(),self.display_filter.get(),self.stream.get(),False)
            code = shell_command(args)+'\n\n# Para a leitura gráfica:\n'+shell_command(['wireshark','-r',source])
            description += ' -r abre o arquivo, -Y filtra, -e escolhe o campo e follow reconstrói a conversa.'
        elif title == 'Codificação':
            code = conversion_script(self.input_text.get('1.0','end-1c'),self.operation.get(),self.key.get(),self.known_prefix.get())
            description += ' O script usa somente a biblioteca padrão do Python e já inclui o texto do campo.'
        elif title == 'Arquivos':
            path = self.file.get() or 'ARQUIVO.bin'
            code = '\n'.join(shell_command(args) for args in [
                ['file','--',path], ['sha256sum','--',path], ['xxd','-l','32',path],
                ['strings','--',path], ['exiftool','-G1','-a','-s','--',path]])
            description += ' Execute uma linha de cada vez para formato, hash, bytes, texto e metadados.'
        elif title == 'Logs':
            code = logs_script(self.log.get() or 'ACESSO.log',self.query.get())
            description += ' O script faz a mesma leitura limitada e o mesmo agrupamento do painel.'
        elif title == 'Portas':
            code = shell_command(nmap_command(self.host.get() or '127.0.0.1',self.ports.get() or '8780-8789'))
            description += ' -sT usa conexão TCP, -Pn pula a descoberta do host e -p escolhe as portas.'
        elif title == 'Web e sessão':
            code = shell_command(web_command(self.web_mode.get(),self.url.get() or 'http://127.0.0.1:8765/',self.cookie.get()))
            description += ' Usa a operação, URL e cookie atuais. O serviço de exemplo fica ativo enquanto esta janela estiver aberta.'
        elif title == 'Gerador de listas':
            code = wordlist_script(self.seeds.get('1.0','end-1c'),self.suffixes.get('1.0','end-1c'),self.variations.get())
            description += ' O script independente salva lista-ctf.txt na pasta atual do terminal.'
        else:
            code = 'sudo apt update\n'+shell_command(['sudo','apt','install',self.package.get()])
            description += ' Execute uma linha de cada vez e aguarde o apt terminar.'
        description += ' Campos vazios usam nomes de exemplo em MAIÚSCULAS; substitua-os pelos seus arquivos.'
        return description, code

    def show_code(self):
        try:
            description, code = self.terminal_preview()
            return show_document(self,'Terminal do Kali · '+self.current_tab,description,code)
        except (ValueError,OSError) as exc:
            messagebox.showerror('Confira os campos',str(exc),parent=self)

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
            ttk.Button(row, text='Selecionar…', style='CtfInfo.TButton', command=lambda: self.browse(variable)).pack(side='left', padx=6)
        return variable

    def browse(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:
            variable.set(path)

    def action(self, frame, text, callback, style='CtfRun.TButton'):
        button = ttk.Button(frame, text=text, command=callback, style=style)
        button.pack(side='left', padx=(0, 8), pady=7)
        self.buttons.append(button)
        if text == 'Executar':
            HoverTip(button, lambda: 'Programa selecionado: '+self.web_mode.get()+'. Usa a URL e o cookie dos campos.')
        else:
            HoverTip(button, ACTION_TOOLS.get(text, 'Abre '+text+' para a ferramenta selecionada.'))

    def example_buttons(self, frame, kind):
        bar = ttk.Frame(frame)
        bar.pack(fill='x')
        self.action(bar, 'Carregar exemplo', lambda: self.load_example(kind), 'CtfExample.TButton')
        self.action(bar, 'Limpar exemplo e saída', lambda: self.clear_example(kind), 'CtfInfo.TButton')

    def explain(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('end', text)
        self.output.configure(state='disabled')

    def load_example(self, kind):
        if self.busy:
            return
        try:
            files = self.examples.files()
            if kind == 'capture':
                self.capture.set(str(files / 'trafego.pcap'))
                self.stream.set('0')
                self.display_filter.set('http')
                explanation = ('1. Em Consultas DNS, clique em Ler com TShark. Procure pacoteazul.ctf.test.\n'
                               '2. Troque para Conversa TCP, índice 0, e execute novamente. Procure CTF{http_em_claro}.\n'
                               '3. Resumo filtrado com http mostra os pacotes HTTP. Abrir no Wireshark oferece a leitura gráfica.')
            elif kind == 'decode':
                operation = self.operation.get()
                text = {'Base64 → texto':'Q1RGe2V4ZW1wbG99', 'Texto → Base64':'CTF{exemplo}',
                        'Hexadecimal → texto':'43 54 46 7b 65 78 65 6d 70 6c 6f 7d',
                        'Texto → hexadecimal':'CTF{exemplo}',
                        'XOR de um byte':'69 7e 6c 51 4f 52 4f 47 5a 46 45 57',
                        'Descobrir chave XOR':'69 7e 6c 51 4f 52 4f 47 5a 46 45 57'}[operation]
                self.input_text.delete('1.0','end')
                self.input_text.insert('1.0',text)
                self.key.set('2a')
                self.known_prefix.set('CTF{')
                explanation = ('1. O exemplo acompanha a operação selecionada. Clique em Converter.\n'
                               '2. Nas decodificações e no XOR, espere CTF{exemplo}. Para codificar, a saída vira Base64 ou hexadecimal.\n'
                               '3. Troque a operação e clique novamente em Carregar exemplo para treinar outra conversão.')
            elif kind == 'file':
                self.file.set(str(files / 'cartao.png'))
                explanation = ('1. Clique em Assinatura, hash e strings. Veja PNG e procure CTF{comentario_png}.\n'
                               '2. Clique em Metadados ExifTool. O campo Comment contém a mesma flag.\n'
                               '3. O hash SHA-256 identifica o conteúdo completo do arquivo. A assinatura identifica seu formato.')
            elif kind == 'logs':
                self.log.set(str(files / 'acesso.log'))
                self.query.set('user=aluno')
                explanation = ('1. Clique em Filtrar e agrupar.\n2. Para 192.0.2.44, observe FAIL → FAIL → FAIL → OK.\n'
                               '3. As tentativas estão intercaladas com outro IP. Conte cada origem separadamente e confira os horários.')
            elif kind in ('ports','web'):
                port = self.examples.start()
                if kind == 'ports':
                    self.host.set('127.0.0.1')
                    self.ports.set(str(port))
                    explanation = (f'1. Um servidor de exemplo foi iniciado neste computador, na porta {port}.\n'
                                   f'2. Clique em Executar Nmap. Espere {port}/tcp open.\n'
                                   '3. A porta pode mudar a cada sessão. O servidor é encerrado ao fechar esta janela.')
                else:
                    mode = self.web_mode.get()
                    route = {'Resposta e cabeçalhos':'/admin', 'SQLmap':'/busca?q=Redes', 'Dalfox (XSS)':'/xss?q=teste'}[mode]
                    self.url.set(f'http://127.0.0.1:{port}'+route)
                    self.cookie.set('')
                    explanation = ('O exemplo iniciou um servidor temporário em localhost.\n'
                                   '• Resposta e cabeçalhos: execute /admin sem cookie (403), depois use papel=admin (200 e CTF{admin_local}).\n'
                                   '• SQLmap: a busca do exemplo usa q=Redes. Execute e leia se o parâmetro q é injetável.\n'
                                   '• Dalfox: o exemplo usa /xss?q=teste. Execute e revise os sinais de reflexão/XSS.\n'
                                   '• Para ver XSS no navegador, abra o formulário e envie <script>provarXSS()</script>. Espere CTF{xss_local}.\n'
                                   'Troque a operação e carregue o exemplo novamente para selecionar a rota correspondente.')
            elif kind == 'wordlist':
                self.seeds.delete('1.0','end'); self.seeds.insert('1.0','aluno\nrede\ncaderno')
                self.suffixes.delete('1.0','end'); self.suffixes.insert('1.0','42\n2026')
                self.variations.set(True)
                explanation = ('1. Clique em Gerar prévia. A lista combina cada palavra com 42 e 2026, além da palavra sem sufixo.\n'
                               '2. A opção de maiúsculas cria variantes como rede, REDE e Rede, sem duplicar linhas.\n'
                               '3. Clique em Gerar e salvar .txt. No John ou Hydra, selecione esse arquivo como wordlist.\n'
                               'A candidata caderno42 serve para o exemplo do John; rede2026 serve para o exemplo do Hydra.')
            else:
                explanation = ('Use os botões de exemplo nas abas. Capturas/Arquivos/Logs recebem arquivos temporários.\n'
                               'Portas/Web iniciam um servidor apenas neste computador. Codificação e Gerador funcionam diretamente em Python.\n'
                               'O John e o Hydra têm janelas próprias: abra pelos atalhos abaixo ou pelo menu principal, e clique em Carregar exemplo.')
            self.explain(explanation)
            self.status.set('Exemplo carregado. Execute a ação indicada. Limpar remove os dados dos campos.')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Exemplo indisponível', str(exc), parent=self)

    def clear_example(self, kind):
        if self.busy:
            return
        fields = {'capture':[self.capture], 'file':[self.file], 'logs':[self.log,self.query],
                  'ports':[self.host,self.ports], 'web':[self.url,self.cookie]}
        for field in fields.get(kind,[]):
            field.set('')
        if kind == 'decode':
            self.input_text.delete('1.0','end')
        if kind == 'wordlist':
            self.seeds.delete('1.0','end'); self.suffixes.delete('1.0','end')
        self.explain('')
        self.status.set('Campos e saída limpos. Carregar exemplo continua disponível quando você quiser.')

    def wordlist_tab(self, frame):
        self.note(frame, 'Uma wordlist é um arquivo com uma candidata por linha. Digite palavras-base e sufixos, como anos. '
                  'A lista mantém também as palavras sem sufixo, remove repetições e limita a geração a 50 mil linhas. '
                  'Use o arquivo salvo no campo Wordlist do Hydra ou Lista de palavras do John.')
        columns = ttk.Frame(frame); columns.pack(fill='x')
        left = ttk.Frame(columns); left.pack(side='left',fill='x',expand=True,padx=(0,8))
        right = ttk.Frame(columns); right.pack(side='left',fill='x',expand=True)
        ttk.Label(left,text='Palavras-base, uma por linha').pack(anchor='w')
        self.seeds = ScrolledText(left,height=4,width=30); self.seeds.pack(fill='x')
        ttk.Label(right,text='Sufixos, um por linha (opcional)').pack(anchor='w')
        self.suffixes = ScrolledText(right,height=4,width=30); self.suffixes.pack(fill='x')
        self.variations = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame,text='Incluir minúsculas, MAIÚSCULAS e Inicial maiúscula',variable=self.variations).pack(anchor='w',pady=5)
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar,'Gerar prévia',self.generate_list)
        self.action(bar,'Gerar e salvar .txt',lambda:self.generate_list(save=True),'CtfInfo.TButton')
        self.example_buttons(frame,'wordlist')

    def generate_list(self, save=False):
        if self.busy:
            return
        try:
            words = generate_wordlist(self.seeds.get('1.0','end-1c'),self.suffixes.get('1.0','end-1c'),self.variations.get())
            path = None
            if save:
                path = filedialog.asksaveasfilename(parent=self,defaultextension='.txt',filetypes=[('Wordlist','*.txt')])
                if not path:
                    return
                save_wordlist(path,words)
            self.explain(f'{len(words)} candidatas únicas. Prévia das primeiras 40:\n\n'+'\n'.join(words[:40])+
                         (f'\n\nArquivo salvo: {path}\nSelecione-o no John ou Hydra.' if path else '\n\nUse Gerar e salvar .txt para exportar a lista completa.'))
            self.status.set(f'Lista gerada: {len(words)} candidatas.')
        except (OSError,ValueError) as exc:
            messagebox.showerror('Gerador de listas',str(exc),parent=self)

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

        self.example_buttons(frame, 'capture')

    def decode_tab(self, frame):
        self.note(frame, 'Cole a evidência. Base64 pode terminar em =. Descobrir chave XOR usa o prefixo informado para recuperar uma chave de um byte. Para XOR, use os bytes em hexadecimal '
                  'e uma chave hexadecimal de um byte, como 2a. O resultado é texto UTF-8 ou bytes em hexadecimal.')
        self.operation = self.field(frame, 'Operação', 'Base64 → texto', choices=[
            'Base64 → texto', 'Texto → Base64', 'Hexadecimal → texto', 'Texto → hexadecimal', 'XOR de um byte', 'Descobrir chave XOR'])
        self.key = self.field(frame, 'Chave XOR hexadecimal', '2a')
        self.known_prefix = self.field(frame,'Prefixo conhecido (XOR)','CTF{')
        self.input_text = ScrolledText(frame, height=4, wrap='word')
        self.input_text.pack(fill='x', pady=5)
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Converter', self.decode)

        self.example_buttons(frame, 'decode')

    def decode(self):
        text, operation, key = self.input_text.get('1.0', 'end-1c'), self.operation.get(), self.key.get()
        if len(text) > 2_000_000:
            return messagebox.showerror('Entrada grande', 'Use até 2 MB de texto.', parent=self)
        prefix = self.known_prefix.get()
        self.local(lambda: transform(text, operation, key, prefix))

    def file_tab(self, frame):
        self.note(frame, 'Identifique assinatura, SHA-256 e texto escondido no arquivo. '
                  'O resumo lê até 2 MB para strings e calcula o hash de todo o arquivo. '
                  'ExifTool mostra os campos de metadados, incluindo comentários PNG quando presentes. Ler resposta HTTP salva separa o status, os cabeçalhos e o corpo de um arquivo .http/.txt.')
        self.file = self.field(frame, 'Arquivo', browse=True)
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Assinatura, hash e strings', self.inspect_file)
        self.action(bar, 'Metadados ExifTool', lambda: self.external(
            lambda: ['exiftool', '-G1', '-a', '-s', local_file(self.file.get())]))

        self.action(bar,'Ler resposta HTTP salva',self.read_http_file,'CtfInfo.TButton')
        self.example_buttons(frame, 'file')
        sample = ttk.Frame(frame)
        sample.pack(fill='x')
        self.action(sample,'Carregar exemplo HTTP',self.load_http_example,'CtfExample.TButton')

    def read_http_file(self):
        path = self.file.get()
        self.local(lambda: http_file_report(path))

    def load_http_example(self):
        if self.busy:
            return
        try:
            self.file.set(str(self.examples.files()/'resposta.http.txt'))
            self.explain('Clique em Ler resposta HTTP salva. Leia X-Lab-Trace na seção CABEÇALHOS. '
                         'O valor é a flag do desafio Cabeçalho suspeito.')
        except OSError as exc:
            messagebox.showerror('Exemplo HTTP',str(exc),parent=self)

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

        self.example_buttons(frame, 'logs')

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

        self.example_buttons(frame, 'ports')

    def scan_ports(self):
        self.external(lambda: nmap_command(self.host.get(),self.ports.get()))

    def web_tab(self, frame):
        self.note(frame, 'Use a URL completa do exercício, incluindo ?q=Redes para SQL ou ?q=teste para XSS. '
                  'Resposta e cabeçalhos permite comparar acessos antes/depois de um cookie. '
                  'Parâmetro e Valor permitem montar uma URL para teste manual de SQL/XSS; os caracteres são codificados automaticamente. Use o alvo do laboratório.')
        self.url = self.field(frame, 'URL', 'http://127.0.0.1:8765/')
        self.cookie = self.field(frame, 'Cookie opcional', '')
        self.parameter = self.field(frame,'Parâmetro de consulta','q')
        self.parameter_value = self.field(frame,'Valor do parâmetro','')
        self.web_mode = self.field(frame, 'Operação', 'Resposta e cabeçalhos', choices=[
            'Resposta e cabeçalhos', 'SQLmap', 'Dalfox (XSS)'])
        bar = ttk.Frame(frame); bar.pack(fill='x')
        self.action(bar, 'Executar', self.run_web)
        self.action(bar, 'Abrir no navegador', self.open_browser)
        self.action(bar,'Montar URL com parâmetro',self.build_query,'CtfInfo.TButton')
        self.note(frame, 'Com o link do CTF Lab, use Executar para importar as flags publicadas ou Abrir no navegador para resolver os desafios.')
        self.note(frame, 'Para aluno → admin, consulte /admin sem cookie e depois com papel=admin. '
                  'Observe o status e o corpo nas duas saídas. Para provar execução de XSS, abra o formulário '
                  'no navegador e siga a missão. O curl exibe HTML como texto.')

        self.example_buttons(frame, 'web')

    def run_web(self):
        if not is_ctf_lab_url(self.url.get()):
            self.external(lambda: web_command(self.web_mode.get(), self.url.get(), self.cookie.get()))
            return
        if self.busy:
            return
        self.begin()
        self.status.set('Carregando os resultados publicados pelo CTF Lab…')

        def worker():
            try:
                results = import_ctf_lab_results()
                if not self.stop_event.is_set():
                    self.events.put(('ctf-flags', results))
                self.events.put(('done', 0))
            except (OSError, ValueError) as exc:
                self.events.put(('log', f'Não foi possível importar as flags do CTF Lab: {exc}'))
                self.events.put(('done', 1))

        threading.Thread(target=worker, daemon=True).start()

    def show_ctf_flags(self, results):
        self.output.configure(state='normal')
        self.output.insert('end', f'CTF Lab · {len(results)} flags publicadas\n\n')
        for index, result in enumerate(results):
            tag = f'ctf-challenge-{index}'
            self.output.tag_configure(tag, foreground='#2877bd', underline=True)
            url = ctf_lab_challenge_url(result['id'])
            self.output.tag_bind(tag, '<Button-1>', lambda event, link=url: webbrowser.open(link))
            self.output.insert('end', f"{result['title']} · {result['category']} — abrir desafio\n", tag)
            self.output.insert('end', f"FLAG  {result['flag']}\n", 'ctf-flag')
            self.output.insert('end', result['explanation']+'\n\n')
        self.output.configure(state='disabled')
        self.output.see('1.0')

    def build_query(self):
        if self.busy:
            return
        try:
            self.url.set(replace_query(self.url.get(),self.parameter.get(),self.parameter_value.get()))
            self.status.set('URL montada. Clique em Executar para ler a resposta ou Abrir no navegador para interpretar o HTML/JS.')
        except ValueError as exc:
            messagebox.showerror('Parâmetro inválido',str(exc),parent=self)

    def open_browser(self):
        try:
            webbrowser.open(target_url(self.url.get()))
        except ValueError as exc:
            messagebox.showerror('URL inválida', str(exc), parent=self)

    def guide_tab(self, frame):
        self.note(frame, '1. Leia o objetivo e escolha a aba pela evidência.\n'
                  '2. Selecione o arquivo ou endereço e execute. A saída aparece abaixo.\n'
                  '3. Leia os campos, monte CTF{resposta} e envie no CTF Lab.\n\n'
                  'John recupera senhas de hashes locais; Hydra testa candidatas num login ativo. Ambos abrem em janelas próprias do Cyberpm. Use os atalhos desta aba ou o menu principal. Nessas janelas, Carregar exemplo prepara os campos, e Limpar exemplo os remove.  Abra as capturas com TShark/Wireshark; '
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

        bar = ttk.Frame(frame); bar.pack(fill='x')
        for name, callback in self.tool_actions.items():
            self.action(bar, 'Abrir '+name, callback, 'CtfInfo.TButton')
        self.example_buttons(frame, 'guide')

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
        self.after_cancel(self.poll_id)
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
            elif kind == 'ctf-flags':
                if not self.stop_event.is_set():
                    self.show_ctf_flags(value)
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
            self.after_cancel(self.poll_id)
            self.stop_event.set()
            self.examples.close()

    def close(self):
        self.stop_event.set()
        self.after_cancel(self.poll_id)
        self.examples.close()
        self.destroy()
