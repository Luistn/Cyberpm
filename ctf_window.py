"""CTF workstation for local evidence and explicit tool runs."""
import binascii
from pathlib import Path
import queue
import re
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from terminal_view import configure_terminal, insert_terminal
import webbrowser
import zipfile

from ctf_tools import (ENCODING_OPERATIONS, FLAG_PATTERN, analyze_ctf_text, capture_command, ctf_lab_address_url, file_report,
                       local_evidence_guide, local_file,
                       log_report, object_access_review, read_http_evidence, target_url, transform, web_command,
                       generate_wordlist, save_wordlist, nmap_command, http_file_report,
                       replace_query, dynamic_xor_report, solve_local_ctf)
from ctf_help import (ACTION_TOOLS, TOOL_GUIDES, HoverTip, conversion_script, logs_script,
                      shell_command, show_document, wordlist_script)
from ctf_examples import CAPTURE_EXERCISES, READING_EXERCISES, CtfExamples
from ctf_importer import ctf_lab_challenge_url, import_ctf_lab_results, is_ctf_lab_url
from ctf_gdb_terminal import GdbTerminal
from ctf_theme import configure_ctf_styles
from sherlock_window import run_process
from study_lists import open_study_lists
from system_install import package_install_command


class CtfWindow(tk.Toplevel):
    def __init__(self, parent, tools=None):
        super().__init__(parent)
        configure_ctf_styles(self)
        self.examples = CtfExamples()
        self.tool_actions = tools or {}
        self.title('CTF · ferramentas e estudo')
        self.geometry('1280x900')
        self.minsize(1000, 720)
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.busy = False
        self.import_guides = {}
        self.analysis_trace = ''
        self.buttons = []
        self.status = tk.StringVar(value='Os resultados da análise aparecem aqui.')
        panes = ttk.Panedwindow(self, orient='horizontal')
        panes.pack(fill='both', expand=True, padx=10, pady=10)
        left = ttk.Frame(panes, padding=(0, 0, 8, 0))
        terminal = ttk.Frame(panes, padding=(8, 0, 0, 0))
        panes.add(left, weight=1)
        panes.add(terminal, weight=2)
        canvas = tk.Canvas(left, borderwidth=0, highlightthickness=0,
                           background=ttk.Style(self).lookup('TFrame', 'background'))
        scrollbar = ttk.Scrollbar(left, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        main = ttk.Frame(canvas)
        content = canvas.create_window(0, 0, window=main, anchor='nw')
        main.bind('<Configure>', lambda event: canvas.configure(scrollregion=canvas.bbox(content)))
        canvas.bind('<Configure>', lambda event: canvas.itemconfigure(content, width=event.width))

        def scroll_tools(event):
            widget = event.widget
            while widget is not None and widget is not canvas:
                widget = widget.master
            if widget is canvas:
                direction = -1 if event.num == 4 or event.delta > 0 else 1
                canvas.yview_scroll(direction, 'units')
                return 'break'

        for sequence in ('<Button-4>', '<Button-5>', '<MouseWheel>'):
            self.bind(sequence, scroll_tools, add='+')

        def initialize_split(event):
            if event.width >= 940:
                panes.sashpos(0, max(500, int(event.width * .46)))
                panes.unbind('<Configure>', split_binding)

        split_binding = panes.bind('<Configure>', initialize_split)
        sources = ttk.LabelFrame(main, text='Abrir desafio', padding=8)
        sources.pack(fill='x', pady=(0, 10))
        sources.columnconfigure((0, 1), weight=1, uniform='sources')
        for index, (label, command) in enumerate((
            ('Colar enunciado…', self.show_ctf_clues),
            ('Abrir arquivo ou ZIP…', self.choose_ctf_to_solve),
            ('Abrir pasta…', lambda: self.choose_ctf_to_solve(folder=True)),
            ('Importar CTF externo…', self.open_importer),
        )):
            ttk.Button(sources, text=label, command=command).grid(
                row=index // 2, column=index % 2, sticky='ew', padx=3, pady=3)

        tools = ttk.LabelFrame(main, text='Ferramentas do CTF', padding=8)
        tools.pack(fill='x', expand=False)
        navigation = ttk.Frame(tools)
        navigation.pack(fill='x', pady=(0, 8))
        navigation.columnconfigure((1, 2, 3, 4), weight=1, uniform='ctf-tabs')
        self.nav_buttons = {}
        self.tab_frames = {}
        self.tool_summary = tk.StringVar()
        help_bar = ttk.Frame(tools)
        help_bar.pack(fill='x', pady=(0, 6))
        ttk.Button(help_bar, text='Como usar esta aba', style='CtfInfo.TButton',
                   command=self.show_help).pack(side='left', padx=(0, 6))
        ttk.Button(help_bar, text='Ver comando', style='CtfInfo.TButton',
                   command=self.show_code).pack(side='left')
        ttk.Label(tools, textvariable=self.tool_summary, wraplength=420, justify='left').pack(anchor='w', pady=(0, 6))
        ttk.Style(self).layout('Ctf.TNotebook.Tab', [])
        notebook = ttk.Notebook(tools, style='Ctf.TNotebook')
        self.notebook = notebook
        notebook.pack(fill='x')
        sections = (
            ('Evidências', (('Arquivos', self.file_tab), ('Codificação', self.decode_tab),
                            ('Capturas', self.capture_tab), ('Logs', self.logs_tab))),
            ('Rede', (('Web e sessão', self.web_tab), ('Portas', self.ports_tab))),
            ('Estudo', (('Gerador de listas', self.wordlist_tab), ('Guia e listas', self.guide_tab))),
        )
        for row, (section, pages) in enumerate(sections):
            ttk.Label(navigation, text=section).grid(row=row, column=0, sticky='w', padx=(0, 6))
            for column, (title, builder) in enumerate(pages, start=1):
                tab = ttk.Frame(notebook, padding=8)
                notebook.add(tab, text=title)
                builder(tab)
                button = ttk.Button(navigation, text=title, style='CtfNav.TButton',
                                    command=lambda name=title: self.select_tab(name))
                span = 2 if len(pages) == 2 else 1
                button.grid(row=row, column=1+(column-1)*span, columnspan=span,
                            sticky='ew', padx=2, pady=2)
                self.nav_buttons[title] = button
                self.tab_frames[title] = tab
        self.notebook.bind('<<NotebookTabChanged>>', self.tab_changed)
        self.notebook.bind('<<NotebookTabChanged>>', lambda event: canvas.yview_moveto(0), add='+')
        self.select_tab('Arquivos')
        terminal_bar = ttk.Frame(terminal)
        terminal_bar.pack(fill='x', pady=(0, 8))
        ttk.Label(terminal_bar, text='Resultados', font=('TkDefaultFont', 11, 'bold')).pack(side='left')
        ttk.Button(terminal_bar, text='Salvar saída…', command=self.save).pack(side='right')
        self.trace_button = ttk.Button(terminal_bar, text='Passos da análise', style='CtfInfo.TButton',
                                       command=self.show_analysis_trace, state='disabled')
        self.trace_button.pack(side='right', padx=6)
        result_actions = ttk.Frame(terminal)
        result_actions.pack(fill='x', pady=(0, 8))
        self.stop_button = ttk.Button(result_actions, text='Parar', style='CtfStop.TButton',
                                      command=self.stop_event.set, state='disabled')
        self.stop_button.pack(side='left', padx=(0, 6))
        ttk.Button(result_actions, text='Evidência importada', style='CtfInfo.TButton',
                   command=self.show_import_guide).pack(side='left')
        assistant = ttk.Button(result_actions, text='✦', style='CtfAssistant.TButton',
                               command=self.open_ctf_assistant)
        assistant.pack(side='left', padx=6)
        HoverTip(assistant, 'Consultar o assistente')
        ttk.Label(terminal, textvariable=self.status, wraplength=470).pack(anchor='w',pady=(0,6))
        self.output = ScrolledText(terminal, wrap='word', state='disabled', height=12, width=48)
        configure_terminal(self.output)
        self.output.tag_configure('ctf-flag', foreground='#7df5ab', background='#123524',
                                  font=('TkFixedFont', 13, 'bold'), spacing1=5, spacing3=5)
        self.output.tag_configure('ctf-answer', foreground='#7dd3fc',
                                  font=('TkDefaultFont', 12, 'bold'), spacing1=5, spacing3=5)
        self.output.tag_configure('ctf-step', foreground='#f9d986')
        self.output.tag_configure('ctf-command', foreground='#65e6d4')
        self.output.tag_configure('ctf-warning', foreground='#fdba74')
        self.output.tag_configure('ctf-error', foreground='#fda4af')
        self.output.pack(fill='both', expand=True)
        self.clues_panel = ttk.LabelFrame(terminal, text='Enunciado ou pistas', padding=6)
        self.clues_input = tk.Text(self.clues_panel, height=4, wrap='word')
        self.clues_input.pack(fill='x')
        ttk.Button(self.clues_panel, text='Analisar localmente', style='CtfRun.TButton',
                   command=self.analyze_pasted_text).pack(side='left', pady=(5, 0))
        send_clues = ttk.Button(self.clues_panel, text='✦', style='CtfAssistant.TButton',
                                command=lambda: self.open_ctf_assistant(
                                    clues=self.clues_input.get('1.0', 'end-1c')))
        send_clues.pack(side='left', padx=(6, 0), pady=(5, 0))
        HoverTip(send_clues, 'Enviar pistas ao assistente')
        ttk.Button(self.clues_panel, text='Ocultar', command=self.clues_panel.pack_forget).pack(side='left', padx=6, pady=(5, 0))
        self.bind('<Control-d>', self.show_ctf_clues)
        self.bind('<Control-D>', self.show_ctf_clues)
        self.poll_id = self.after(100, self.poll)
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.bind('<Destroy>', self.on_destroy, add='+')

    def choose_ctf_to_solve(self, *, folder=False):
        if self.busy:
            return
        from ctf_import_window import request_zip_password

        path = (filedialog.askdirectory(parent=self, title='Escolha a pasta do CTF', mustexist=True)
                if folder else filedialog.askopenfilename(parent=self, title='Escolha o arquivo do CTF'))
        if path:
            try:
                proceed, password = request_zip_password(self, path)
            except (OSError, zipfile.BadZipFile) as exc:
                self.status.set(f'Não foi possível ler o ZIP: {exc}')
                return
            if not proceed:
                self.status.set('Análise cancelada.')
                return
            self.select_tab('Arquivos')
            self.file.set(path)
            self.local(lambda: solve_local_ctf(path, self.stop_event, zip_password=password), cancellable=True)

    def show_ctf_clues(self, _event=None):
        self.clues_panel.pack(fill='x', pady=(0, 6), before=self.output)
        self.clues_input.focus_set()
        return 'break'

    def analyze_pasted_text(self):
        text = self.clues_input.get('1.0', 'end-1c')
        self.local(lambda: analyze_ctf_text(text))

    def open_ctf_assistant(self, *, clues=None):
        if self.busy:
            return
        from ctf_import_window import analyze_evidence, load_config, request_zip_password

        selection = self.output.tag_ranges('sel')
        evidence = clues.strip() if clues is not None else self.output.get(*selection).strip() if selection else ''
        if clues is not None and not evidence:
            self.status.set('Digite ou cole uma pista antes de analisar.')
            return
        fields = {'Arquivos': self.file, 'Capturas': self.capture, 'Logs': self.log}
        field = fields.get(self.current_tab)
        path = field.get().strip() if field is not None else ''
        if not evidence and not path:
            self.status.set('Abra um arquivo ou selecione um trecho da saída para analisar.')
            return
        if len(evidence) > 12000:
            self.status.set('Selecione um trecho de até 12.000 caracteres.')
            return
        try:
            proceed, password = (True, None) if evidence else request_zip_password(self, path)
        except (OSError, zipfile.BadZipFile) as exc:
            self.status.set(f'Não foi possível ler o ZIP: {exc}')
            return
        if not proceed:
            self.status.set('Análise cancelada.')
            return
        config = load_config()
        self.begin(keep_output=clues is not None)

        def worker():
            code = 0
            try:
                if not evidence:
                    report = solve_local_ctf(path, self.stop_event, zip_password=password)
                    self.events.put(('evidence-result', report))
                    if self.stop_event.is_set():
                        return
                    if FLAG_PATTERN.search(report):
                        self.events.put(('log', '\nA análise local encontrou um texto com formato de flag. '
                                         'O assistente não foi consultado. Confira no relatório se o valor '
                                         'é uma flag de teste ou do desafio.\n'))
                        return
                if not config.get('api_key'):
                    self.events.put(('log', '\nConfigure uma chave para usar o assistente do CyberPM.\n'))
                    code = 1
                    return
                excerpt = report if password is not None else evidence
                answer = analyze_evidence(Path(path), config, excerpt=excerpt)
                if not self.stop_event.is_set():
                    self.events.put(('log', '\nAssistente · análise da evidência\n\n' + answer + '\n'))
            except (OSError, ValueError, RuntimeError, KeyError, IndexError, TypeError) as exc:
                code = 1
                if not self.stop_event.is_set():
                    detail = f'HTTP {exc.code}' if hasattr(exc, 'code') else str(exc)
                    self.events.put(('log', f'\nNão foi possível concluir a análise: {detail}\n'))
            finally:
                self.events.put(('done', code))

        threading.Thread(target=worker, daemon=True).start()

    def open_importer(self):
        from ctf_import_window import ImportCtfWindow
        window = getattr(self,'import_window',None)
        if window is not None and window.winfo_exists():
            window.lift()
            return window
        self.import_window = ImportCtfWindow(self, self.open_imported_file, self.use_imported_url,
                                            open_evidence=self.open_local_evidence)
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
        self.explain('Arquivo importado e encaminhado para '+title+':\n'+path+
                     '\n\nA análise inicial será executada automaticamente. A saída aparece abaixo; '
                     'respostas e flags ficam destacadas. Use “Como usar no CTF” para o passo a passo.')
        if title == 'Arquivos':
            name = Path(path).name.lower()
            try:
                is_elf = Path(path).read_bytes()[:4] == b'\x7fELF'
            except OSError:
                is_elf = False
            if name == 'main.py':
                self.after(150, self.solve_dynamic_challenge)
            elif is_elf:
                self.after(150, self.inspect_file)
                self.after(300, lambda selected=path: self.open_gdb_terminal(selected))
            else:
                self.after(150, self.inspect_file)
        self.lift()

    def open_local_evidence(self, tool, path):
        suggested, args, steps = local_evidence_guide(path)
        if tool == 'Codificação':
            try:
                with Path(path).open(encoding='utf-8') as handle:
                    text = handle.read(2_000_001)
                if len(text) > 2_000_000:
                    raise ValueError('A aba Codificação recebe até 2 MB de texto.')
            except (OSError, ValueError) as exc:
                messagebox.showerror('Codificação', str(exc), parent=self)
                return
            self.operation.set(ENCODING_OPERATIONS.get(Path(path).suffix.lower(), 'Base64 → texto'))
            self.input_text.delete('1.0', 'end')
            self.input_text.insert('1.0', text)
        elif tool == 'Capturas':
            self.capture.set(path)
            self.capture_mode.set('Resumo filtrado')
            self.display_filter.set('')
        elif tool == 'Logs':
            self.log.set(path)
            self.query.set('')
        else:
            self.file.set(path)
        self.select_tab(tool)
        importer = getattr(self, 'import_window', None)
        info = importer.info if importer is not None and importer.winfo_exists() else None
        guide = f'{Path(path).name} · {suggested}\n\n{steps}\n\nTerminal do Kali\n{shell_command(args)}'
        self.import_guides[tool] = guide, info
        if not self.busy:
            self.explain(guide)
            if tool == 'Arquivos':
                prefix = ('Importação: abri as entradas protegidas do ZIP com a senha informada.\n\n'
                          if info and info.get('opened_protected_entries') else '')
                self.local(lambda: prefix + solve_local_ctf(path, self.stop_event), cancellable=True)
        self.lift()

    def show_import_guide(self):
        entry = self.import_guides.get(self.current_tab)
        if entry is None:
            self.status.set('Abra uma evidência importada nesta aba para ver o roteiro.')
            return
        guide, info = entry
        if info is not None:
            answer = info.get('deepseek_answer')
            if answer:
                guide += '\n\nAssistente · análise da importação\n\n' + answer
            elif info.get('deepseek_pending'):
                guide += '\n\nO assistente está analisando a importação.'
            elif info.get('deepseek_error'):
                guide += '\n\nFalha na análise do assistente: ' + info['deepseek_error']
        show_document(self, 'Evidência importada · ' + self.current_tab,
                      'Roteiro da evidência selecionada', guide)

    def use_imported_url(self, url):
        self.select_tab('Web e sessão')
        self.url.set(target_url(url))
        self.cookie.set('')
        self.parameter_value.set('')
        self.web_mode.set('Resposta e cabeçalhos')
        guide = (f'{url}\n\nAbra a página no navegador e leia o enunciado. '
                 'Para análise pelo assistente, salve o enunciado ou a resposta HTTP e importe o arquivo. '
                 'Para uma resposta HTTP salva, veja o status, os cabeçalhos e o corpo em Arquivos.\n\n'
                 'Terminal do Kali\n' + shell_command(['xdg-open', url]))
        self.import_guides['Web e sessão'] = guide, None
        self.explain(guide)
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
            button.configure(style='CtfInfo.TButton' if name == title else 'CtfNav.TButton')

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
        ttk.Label(frame, text=text, wraplength=470, justify='left').pack(anchor='w', pady=(0, 8))

    def tab_group(self, parent, title):
        group = ttk.LabelFrame(parent, text=title, padding=(8, 6))
        group.pack(fill='x', pady=(0, 6))
        return group

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
        group = self.tab_group(frame, 'Praticar com exemplos')
        names = tuple(CAPTURE_EXERCISES if kind == 'capture' else READING_EXERCISES.get(kind, ()))
        choices = {'Exemplo inicial': lambda: self.load_example(kind),
                   'Exemplo complementar': lambda: self.load_extra_example(kind)}
        choices.update({name: lambda name=name: self.load_practice_example(kind, name) for name in names})
        selected = self.field(group, 'Exemplo', next(iter(choices)), choices=tuple(choices))
        bar = ttk.Frame(group)
        bar.pack(fill='x')
        self.action(bar, 'Carregar exemplo', lambda: choices[selected.get()](), 'CtfExample.TButton')
        self.action(bar, 'Limpar', lambda: self.clear_example(kind), 'CtfInfo.TButton')

    def load_practice_example(self, kind, name):
        if self.busy:
            return
        if kind == 'capture':
            try:
                capture = self.examples.files() / 'trafego.pcap'
            except OSError as error:
                messagebox.showerror('Exemplo indisponível', str(error), parent=self)
                return
            mode, display_filter, instruction = CAPTURE_EXERCISES[name]
            self.capture.set(str(capture))
            self.capture_mode.set(mode)
            self.display_filter.set(display_filter)
            self.stream.set('0')
            report = f'{instruction}\n\nUse Ler com TShark ou Abrir no Wireshark.'
            if display_filter:
                report += f' No Wireshark, aplique o filtro {display_filter}.'
        else:
            report = READING_EXERCISES[kind][name]
        self.explain(f'{name}\n\n{report}')
        self.status.set('Exercício carregado. Veja as instruções nos resultados.')

    def load_extra_example(self, kind):
        if self.busy:
            return
        try:
            files = self.examples.files()
            if kind == 'capture':
                self.capture.set(str(files / 'trafego.pcap'))
                self.display_filter.set('dns')
                explanation = ('Exercício: nomes DNS em uma captura.\n'
                               'Escolha Resumo filtrado e clique em Ler com TShark. '
                               'Identifique o nome pacoteazul.ctf.test no tráfego DNS.')
            elif kind == 'decode':
                self.operation.set('Hexadecimal → texto')
                self.input_text.delete('1.0', 'end')
                self.input_text.insert('1.0', b'CTF{mapa_hex}'.hex(' '))
                explanation = 'Clique em Converter. A saída esperada é CTF{mapa_hex}.'
            elif kind == 'file':
                self.file.set(str(files / 'resposta.http.txt'))
                explanation = ('Clique em Assinatura, hash e strings. Identifique o arquivo como texto e '
                               'localize a linha de status HTTP entre as strings.')
            elif kind == 'logs':
                self.log.set(str(files / 'eventos_exemplo.log'))
                self.query.set('user=ana')
                explanation = ('Clique em Filtrar e agrupar. Ignore as linhas de bia e identifique '
                               'a sequência FAIL → OK da origem 192.0.2.12.')
            elif kind == 'ports':
                explanation = ('Exercício de leitura de um resultado simulado.\n'
                               '22/tcp closed\n443/tcp open\n8443/tcp filtered\n\n'
                               'Qual porta respondeu como aberta? 443. A porta 8443 ficou filtrada.')
            elif kind == 'web':
                explanation = ('Exercício de leitura de respostas HTTP simuladas.\n'
                               'GET /perfil → HTTP 302, Location: /login\n'
                               'GET /login → HTTP 200, Content-Type: text/html\n\n'
                               'O primeiro status indica redirecionamento. O segundo indica que a página de login foi entregue.')
            elif kind == 'wordlist':
                self.seeds.delete('1.0', 'end')
                self.seeds.insert('1.0', 'mapa\nfarol')
                self.suffixes.delete('1.0', 'end')
                self.suffixes.insert('1.0', '07\n09')
                self.variations.set(False)
                explanation = 'Clique em Gerar prévia. Confira seis itens, incluindo mapa, mapa07 e farol09.'
            else:
                explanation = ('Exercício guiado: cole Q1RGe21hcGF9 na aba Codificação, escolha '
                               'Base64 → texto e clique em Converter. Confira CTF{mapa} na saída.')
            self.explain(explanation)
            self.status.set('Outro exemplo carregado. Veja as instruções nos resultados.')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Exemplo indisponível', str(exc), parent=self)

    def explain(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.insert_terminal_text(text)
        self.output.configure(state='disabled')

    def insert_terminal_text(self, text):
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            lowered = stripped.lower()
            tag = None
            if re.match(r'^(?:\d+\. )?(?:comando|código python):', lowered):
                tag = 'ctf-command'
            elif lowered.startswith(('não foi possível', 'falha', 'erro', 'traceback')):
                tag = 'ctf-error'
            elif lowered.startswith(('nenhuma flag', 'aviso', 'a evidência contém uma flag de teste')):
                tag = 'ctf-warning'
            elif stripped in ('Passos executados', 'Resultado') or lowered.startswith('assistente ·'):
                tag = 'ctf-answer'
            elif re.match(r'^\d+\. ', stripped):
                tag = 'ctf-step'
            elif FLAG_PATTERN.search(line):
                tag = 'ctf-flag'
            insert_terminal(self.output, line, tag)

    def show_analysis_trace(self):
        if self.analysis_trace:
            return show_document(self, 'O que eu fiz · CTF',
                                 'Etapas, código e ferramentas registrados na última análise local.',
                                 self.analysis_trace)

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
        custom = self.tab_group(frame, 'Lista personalizada')
        columns = ttk.Frame(custom)
        columns.pack(fill='x')
        left = ttk.Frame(columns); left.pack(side='left',fill='x',expand=True,padx=(0,8))
        right = ttk.Frame(columns); right.pack(side='left',fill='x',expand=True)
        ttk.Label(left,text='Palavras-base, uma por linha').pack(anchor='w')
        self.seeds = ScrolledText(left,height=4,width=30); self.seeds.pack(fill='x')
        ttk.Label(right,text='Sufixos, um por linha (opcional)').pack(anchor='w')
        self.suffixes = ScrolledText(right,height=4,width=30); self.suffixes.pack(fill='x')
        self.variations = tk.BooleanVar(value=True)
        ttk.Checkbutton(custom,text='Incluir minúsculas, MAIÚSCULAS e Inicial maiúscula',variable=self.variations).pack(anchor='w',pady=5)
        bar = ttk.Frame(custom); bar.pack(fill='x')
        self.action(bar,'Gerar prévia',self.generate_list)
        self.action(bar,'Gerar e salvar .txt',lambda:self.generate_list(save=True),'CtfInfo.TButton')
        datasets = self.tab_group(frame, 'Sequências e listas prontas')
        self.action(datasets, 'Abrir gerador de sequências', lambda: open_study_lists(self))
        self.example_buttons(frame, 'wordlist')

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
        self.capture = self.field(frame, 'Arquivo de captura', browse=True)
        options = self.tab_group(frame, 'Leitura da captura')
        self.capture_mode = self.field(options, 'Operação', 'Consultas DNS', choices=[
            'Consultas DNS', 'Conversa TCP', 'Resumo filtrado'])
        self.display_filter = self.field(options, 'Filtro do resumo', 'http')
        self.stream = self.field(options, 'Índice da conversa TCP', '0')
        bar = ttk.Frame(options); bar.pack(fill='x')
        self.action(bar, 'Ler com TShark', lambda: self.external(lambda: capture_command(
            self.capture.get(), self.capture_mode.get(), self.display_filter.get(), self.stream.get())))
        self.action(bar, 'Abrir no Wireshark', lambda: self.external(
            lambda: ['wireshark', '-r', local_file(self.capture.get())]))

        self.example_buttons(frame, 'capture')

    def decode_tab(self, frame):
        conversion = self.tab_group(frame, 'Conversão')
        self.operation = self.field(conversion, 'Operação', 'Base64 → texto', choices=[
            'Base64 → texto', 'Texto → Base64', 'Hexadecimal → texto', 'Texto → hexadecimal', 'XOR de um byte', 'Descobrir chave XOR'])
        evidence = self.tab_group(conversion, 'Texto ou bytes em hexadecimal')
        self.input_text = ScrolledText(evidence, height=4, wrap='word')
        self.input_text.pack(fill='x', pady=5)
        xor = self.tab_group(conversion, 'Opções de XOR')
        self.key = self.field(xor, 'Chave de um byte em hexadecimal', '2a')
        self.known_prefix = self.field(xor, 'Prefixo conhecido para descobrir a chave', 'CTF{')
        bar = ttk.Frame(conversion); bar.pack(fill='x')
        self.action(bar, 'Converter', self.decode)

        self.example_buttons(frame, 'decode')

    def decode(self):
        text, operation, key = self.input_text.get('1.0', 'end-1c'), self.operation.get(), self.key.get()
        if len(text) > 2_000_000:
            return messagebox.showerror('Entrada grande', 'Use até 2 MB de texto.', parent=self)
        prefix = self.known_prefix.get()
        self.local(lambda: transform(text, operation, key, prefix))

    def file_tab(self, frame):
        self.file = self.field(frame, 'Arquivo', browse=True)
        bar = self.tab_group(frame, 'Inspeção de arquivos')
        self.action(bar, 'Assinatura, hash e strings', self.inspect_file)
        self.action(bar, 'Metadados ExifTool', lambda: self.external(
            lambda: ['exiftool', '-G1', '-a', '-s', local_file(self.file.get())]))

        self.action(bar,'Ler resposta HTTP salva',self.read_http_file,'CtfInfo.TButton')
        special = self.tab_group(frame, 'Imagens e desafios de binário ou código')
        image_actions = ttk.Frame(special)
        image_actions.pack(fill='x')
        self.action(image_actions,'Resolver XOR crazyx0r',self.solve_dynamic_challenge,'CtfExample.TButton')
        self.action(image_actions,'Extrair dados da imagem',self.extract_hidden_image,'CtfRun.TButton')
        binary_actions = ttk.Frame(special)
        binary_actions.pack(fill='x')
        self.action(binary_actions,'Analisar binário com GDB',self.analyze_binary_gdb,'CtfInfo.TButton')
        self.action(binary_actions,'Terminal interativo GDB',self.open_gdb_terminal,'CtfExample.TButton')
        sample = self.tab_group(frame, 'Exemplos')
        self.example_buttons(sample, 'file')
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

    def solve_dynamic_challenge(self):
        path = self.file.get()
        self.local(lambda: dynamic_xor_report(path))

    def extract_hidden_image(self):
        if self.busy:
            return
        try:
            path = local_file(self.file.get())
            data = Path(path).read_bytes()[:2_000_000]
            match = re.search(rb'Senha\s*:\s*([^\s\x00]+)', data, re.IGNORECASE)
            if not match:
                raise ValueError('Não encontrei uma senha em texto no começo da imagem. Rode primeiro Assinatura, hash e strings.')
            password = match.group(1).decode('utf-8', errors='replace')
            destination = path + '.extraido'
            self.external(lambda: ['steghide','extract','-sf',path,'-p',password,'-xf',destination,'-f'])
            self.pending_extract = destination
        except (OSError, ValueError) as exc:
            messagebox.showerror('Extração de imagem', str(exc), parent=self)

    def analyze_binary_gdb(self):
        try:
            path = local_file(self.file.get())
            if Path(path).read_bytes()[:4] != b'\\x7fELF':
                raise ValueError('Selecione o executável ELF do desafio (por exemplo, br0k3n).')
            self.external(lambda: ['gdb','--batch','--nx','--se',path,
                '-ex','info functions', '-ex','disassemble main',
                '-ex','disassemble gerar_chave_secreta', '-ex','disassemble revelar_flag'])
        except (OSError, ValueError) as exc:
            messagebox.showerror('Análise GDB', str(exc), parent=self)

    def open_gdb_terminal(self, path=None):
        try:
            binary = local_file(path or self.file.get())
            if Path(binary).read_bytes()[:4] != b'\x7fELF':
                raise ValueError('Selecione um executável ELF, como br0k3n.')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Terminal GDB', str(exc), parent=self)
            return
        existing = getattr(self, 'gdb_console_window', None)
        if existing is not None and existing.winfo_exists():
            if str(existing.binary) == binary:
                existing.lift()
                return existing
            existing.close()
        if not shutil.which('gdb'):
            if self.busy:
                messagebox.showinfo('Instalação do GDB', 'Aguarde o processo CTF atual terminar e tente abrir o terminal GDB novamente.', parent=self)
                return
            install_args = package_install_command(self, 'GDB', 'gdb')
            if install_args:
                self.open_gdb_after_install = binary
                self.launch(install_args)
            return
        self.gdb_console_window = GdbTerminal(self, binary)
        return self.gdb_console_window

    def logs_tab(self, frame):
        self.log = self.field(frame, 'Arquivo de log', browse=True)
        bar = self.tab_group(frame, 'Filtro e agrupamento')
        self.query = self.field(bar, 'Texto a procurar (opcional)')
        self.note(bar, 'Exemplo de filtro: user=aluno. O agrupamento usa IP, usuário e eventos FAIL/OK.')
        self.action(bar, 'Filtrar e agrupar', self.inspect_log)

        self.example_buttons(frame, 'logs')

    def inspect_log(self):
        path, query = self.log.get(), self.query.get()
        self.local(lambda: log_report(path, query))

    def ports_tab(self, frame):
        target = self.tab_group(frame, 'Alvo e portas do laboratório')
        self.host = self.field(target, 'Host ou IP', '127.0.0.1')
        self.ports = self.field(target, 'Portas ou intervalo', '8780-8789')
        bar = ttk.Frame(target); bar.pack(fill='x')
        self.action(bar, 'Executar Nmap', self.scan_ports)

        self.example_buttons(frame, 'ports')

    def scan_ports(self):
        self.external(lambda: nmap_command(self.host.get(),self.ports.get()))

    def web_tab(self, frame):
        lab = self.tab_group(frame, 'Instância do laboratório')
        self.lab_address = self.field(lab, 'IP e porta (opcional)', '')
        lab_actions = ttk.Frame(lab)
        lab_actions.pack(fill='x')
        self.action(lab_actions, 'Abrir instância', self.open_ctf_lab_address, 'CtfInfo.TButton')
        self.action(lab_actions, 'Colar pistas (Ctrl+D)', self.show_ctf_clues, 'CtfNav.TButton')
        self.url = self.field(frame, 'URL do site', 'http://127.0.0.1:8765/')
        access = ttk.Frame(frame)
        access.pack(fill='x', pady=(0, 8))
        self.action(access, 'Abrir no navegador', self.open_browser)
        self.action(access, 'Revisar IDOR/BOLA', self.review_object_access, 'CtfInfo.TButton')
        tools = ttk.LabelFrame(frame, text='Ferramentas do exercício', padding=6)
        tools.pack(fill='x')
        self.cookie = self.field(tools, 'Cookie opcional', '')
        self.web_mode = self.field(tools, 'Operação', 'Resposta e cabeçalhos', choices=[
            'Resposta e cabeçalhos', 'SQLmap', 'Dalfox (XSS)'])
        bar = ttk.Frame(tools); bar.pack(fill='x')
        self.action(bar, 'Executar', self.run_web)
        parameters = ttk.LabelFrame(frame, text='Parâmetros da URL', padding=6)
        parameters.pack(fill='x', pady=5)
        self.parameter = self.field(parameters, 'Parâmetro de consulta', 'q')
        self.parameter_value = self.field(parameters, 'Valor do parâmetro', '')
        bar = ttk.Frame(parameters); bar.pack(fill='x')
        self.action(bar,'Montar URL com parâmetro',self.build_query,'CtfInfo.TButton')
        self.example_buttons(frame, 'web')

    def open_ctf_lab_address(self):
        address = self.lab_address.get().strip()
        try:
            url = ctf_lab_address_url(address) if address else self.web_address()
        except ValueError as exc:
            self.status.set(str(exc))
            return
        webbrowser.open(url)
        self.status.set('Instância aberta no navegador. Use Ctrl+D para colar as pistas que observar.')

    def web_address(self):
        value = self.url.get().strip()
        if value.startswith('//'):
            value = 'https:' + value
        elif value and '://' not in value:
            value = 'https://' + value
        return target_url(value)

    def review_object_access(self):
        try:
            url = target_url(self.url.get())
        except ValueError as exc:
            messagebox.showerror('Confira a URL', str(exc), parent=self)
            return
        panel = tk.Toplevel(self)
        panel.title('Revisar IDOR/BOLA')
        panel.geometry('850x650')
        panel.transient(self)
        frame = ttk.Frame(panel, padding=12)
        frame.pack(fill='both', expand=True)
        self.note(frame, f'Serviço em revisão: {url}')
        self.note(frame, 'Cole as respostas HTTP completas, incluindo a linha de status, '
                         'para a mesma operação e o mesmo objeto.')
        inputs = []
        for label in ('Resposta da conta autorizada', 'Resposta da conta que deveria receber recusa'):
            group = ttk.LabelFrame(frame, text=label, padding=6)
            group.pack(fill='both', expand=True, pady=(0, 6))
            field = ScrolledText(group, height=7, wrap='word')
            field.pack(fill='both', expand=True)
            inputs.append(field)
            ttk.Button(group, text='Carregar resposta UTF-8…',
                       command=lambda widget=field: self.load_review_response(panel, widget)).pack(anchor='w')

        def compare():
            try:
                responses = [field.get('1.0', 'end-1c').encode('utf-8') for field in inputs]
                report = object_access_review(*responses)
            except ValueError as exc:
                messagebox.showerror('Confira as respostas', str(exc), parent=panel)
                return
            panel.destroy()
            self.explain(f'Serviço em revisão: {url}\n\n{report}')
            self.status.set('Comparação concluída. Veja o relatório na saída.')

        ttk.Button(frame, text='Comparar respostas', command=compare).pack(anchor='w')

    def load_review_response(self, panel, field):
        path = filedialog.askopenfilename(parent=panel, title='Carregar resposta HTTP')
        if not path:
            return
        try:
            data = read_http_evidence(path)
            if len(data) > 2_000_000:
                raise ValueError('Use uma resposta HTTP com até 2 MB.')
            text = data.decode('utf-8')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Carregar resposta', str(exc), parent=panel)
            return
        field.delete('1.0', 'end')
        field.insert('1.0', text)

    def run_web(self):
        if self.web_mode.get() == 'Resposta e cabeçalhos':
            try:
                self.url.set(self.web_address())
            except ValueError as exc:
                messagebox.showerror('Confira a URL do site', str(exc), parent=self)
                return
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
            self.output.tag_configure(tag, foreground='#7dd3fc', underline=True)
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
            webbrowser.open(self.web_address())
        except ValueError as exc:
            messagebox.showerror('URL inválida', str(exc), parent=self)

    def guide_tab(self, frame):
        planning = self.tab_group(frame, 'Escolher pela evidência')
        self.note(planning, 'PCAP em Capturas · Base64 ou hexadecimal em Codificação · '
                            'Imagem ou resposta HTTP salva em Arquivos · Registros em Logs.')
        packages = self.tab_group(frame, 'Pacotes do Kali')
        self.package = self.field(packages, 'Pacote do Kali', 'tshark', choices=[
            'tshark', 'wireshark', 'nmap', 'curl', 'sqlmap', 'dalfox', 'seclists', 'libimage-exiftool-perl'])
        bar = ttk.Frame(packages); bar.pack(fill='x')
        self.action(bar, 'Instalar pacote escolhido', self.install)
        bar = self.tab_group(frame, 'Material de estudo')
        self.action(bar, 'Abrir histórias e guias', lambda: webbrowser.open(
            'https://ctf-lab-estudos-mwkq0dq4.hushedcrab131.chatgpt.site/#guias'))
        self.action(bar, 'Revisão para a prova', lambda: webbrowser.open(
            'https://ctf-lab-estudos-mwkq0dq4.hushedcrab131.chatgpt.site/revisao?v=prova'), 'CtfInfo.TButton')
        if self.tool_actions:
            shortcuts = self.tab_group(frame, 'Ferramentas do CyberPM')
            for name, callback in self.tool_actions.items():
                self.action(shortcuts, 'Abrir '+name, callback, 'CtfInfo.TButton')
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
                package = {'exiftool': 'libimage-exiftool-perl',
                           'steghide': 'steghide', 'gdb': 'gdb'}.get(args[0], args[0])
                install_args = package_install_command(self, args[0], package)
                if install_args:
                    self.retry_after_install = args
                    self.launch(install_args)
                return
            args[0] = executable
            self.launch(args)
        except (ValueError, OSError) as exc:
            messagebox.showerror('Confira os campos', str(exc), parent=self)

    def launch(self, args):
        self.begin()
        # Cookies can contain session secrets, so commands are not echoed.
        threading.Thread(target=run_process, args=(args, self.stop_event, self.events, 'CTF'), daemon=True).start()

    def local(self, callback, *, cancellable=False):
        if self.busy:
            return
        self.begin()
        if not cancellable:
            self.stop_button.configure(state='disabled')
        def worker():
            try:
                self.events.put(('evidence-result', callback()))
                self.events.put(('done', 0))
            except (ValueError, OSError, binascii.Error) as exc:
                self.events.put(('log', f'Não foi possível processar: {exc}'))
                self.events.put(('done', 1))
        threading.Thread(target=worker, daemon=True).start()

    def show_evidence_result(self, text):
        if '\nPassos executados\n' in text:
            self.analysis_trace = text
            self.trace_button.configure(state='normal')
        flags = dict.fromkeys(FLAG_PATTERN.findall(text))
        self.output.configure(state='normal')
        if flags:
            self.output.insert('end', 'Flags encontradas na evidência\n', 'result')
            for flag in flags:
                self.output.insert('end', f'{flag}\n', 'ctf-flag')
            self.output.insert('end', '\n')
            self.insert_terminal_text(text)
        elif 'candidato:' in text:
            self.output.insert('end', 'SAÍDA DA ANÁLISE\n', 'result')
            for line in text.splitlines(keepends=True):
                insert_terminal(self.output, line, 'ctf-flag' if 'candidato:' in line else None)
        else:
            self.output.insert('end', 'SAÍDA DA ANÁLISE\n', 'result')
            self.insert_terminal_text(text)
        self.output.configure(state='disabled')
        self.output.see('1.0')

    def begin(self, *, keep_output=False):
        self.busy = True
        self.stop_event.clear()
        if not keep_output:
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
                self.insert_terminal_text(value)
                # Bound the visible output without blocking process drainage.
                if int(self.output.index('end-1c').split('.')[0]) > 12000:
                    self.output.delete('1.0', '2001.0')
                self.output.see('end')
                self.output.configure(state='disabled')
            elif kind == 'evidence-result':
                self.show_evidence_result(value)
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
                extracted = getattr(self, 'pending_extract', None)
                retry = getattr(self, 'retry_after_install', None)
                open_gdb = getattr(self, 'open_gdb_after_install', None)
                self.pending_extract = self.retry_after_install = self.open_gdb_after_install = None
                if value != 0 or self.stop_event.is_set():
                    continue
                if extracted and Path(extracted).is_file():
                    self.file.set(extracted)
                    self.after(100, self.inspect_file)
                if retry:
                    self.after(100, lambda args=retry: self.external(lambda: list(args)))
                if open_gdb:
                    self.after(150, lambda selected=open_gdb: self.open_gdb_terminal(selected))
        self.poll_id = self.after(100, self.poll)

    def save(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.txt')
        if path:
            try:
                Path(path).write_text(self.output.get('1.0', 'end-1c'), encoding='utf-8')
                self.status.set(f'Saída salva em {path}')
            except OSError as exc:
                messagebox.showerror('Falha ao salvar', str(exc), parent=self)

    def on_destroy(self, event):
        if event.widget is self:
            self.after_cancel(self.poll_id)
            self.stop_event.set()
            self.examples.close()
            terminal = getattr(self, 'gdb_console_window', None)
            if terminal is not None and terminal.winfo_exists():
                terminal.close()

    def close(self):
        self.stop_event.set()
        self.after_cancel(self.poll_id)
        self.examples.close()
        self.destroy()
