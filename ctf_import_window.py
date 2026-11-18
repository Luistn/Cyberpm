"""Optional import of external evidence, URLs and lab packages."""
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import zipfile

from ctf_help import HoverTip, shell_command, show_document
from ctf_importer import import_ctf_lab_results, import_package, is_ctf_lab_url, write_template
from ctf_theme import configure_ctf_styles
from ctf_tools import target_url


class ImportCtfWindow(tk.Toplevel):
    def __init__(self, parent, open_file, use_url):
        super().__init__(parent)
        configure_ctf_styles(self)
        self.title('Importar CTF externo · arquivos e laboratório')
        self.geometry('1020x800')
        self.minsize(760,620)
        self.open_file = open_file
        self.use_url = use_url
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.busy = False
        self.info = None
        self.files = {}
        frame = ttk.Frame(self,padding=12)
        frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='Cole o link do CTF Lab ou escolha uma evidência, um pacote ZIP ou a pasta do laboratório. '
                  'O enunciado é lido de README/enunciado ou do manifesto opcional ctf.json. '
                  'Os pacotes são copiados para ~/.config/cyberpm/ctf-imports.',wraplength=960).pack(anchor='w',pady=(0,8))
        self.source = tk.StringVar()
        row = ttk.Frame(frame)
        row.pack(fill='x')
        ttk.Entry(row,textvariable=self.source).pack(side='left',fill='x',expand=True)
        ttk.Button(row,text='Arquivo ou ZIP…',style='CtfInfo.TButton',command=self.browse_file).pack(side='left',padx=6)
        ttk.Button(row,text='Pasta…',style='CtfInfo.TButton',command=self.browse_folder).pack(side='left')
        bar = ttk.Frame(frame)
        bar.pack(fill='x',pady=7)
        self.import_button = ttk.Button(bar,text='Importar / abrir',style='CtfRun.TButton',command=self.start)
        self.import_button.pack(side='left')
        self.stop_button = ttk.Button(bar,text='Parar importação',style='CtfStop.TButton',command=self.stop.set,state='disabled')
        self.stop_button.pack(side='left',padx=8)
        ttk.Label(bar,text='Limite de extração (MiB)').pack(side='left')
        self.limit = tk.StringVar(value='512')
        ttk.Entry(bar,textvariable=self.limit,width=7).pack(side='left',padx=6)
        ttk.Button(bar,text='Criar pacote modelo…',style='CtfExample.TButton',command=self.template).pack(side='left')
        self.status = tk.StringVar(value='Escolha os arquivos ou informe uma URL abaixo.')
        ttk.Label(frame,textvariable=self.status,wraplength=960).pack(anchor='w',pady=5)
        files_frame = ttk.Frame(frame)
        files_frame.pack(fill='x')
        self.tree = ttk.Treeview(files_frame,columns=('size',),height=6)
        self.tree.heading('#0',text='Arquivos disponíveis')
        self.tree.heading('size',text='Bytes')
        self.tree.column('size',width=100,stretch=False)
        self.tree.pack(side='left',fill='x',expand=True)
        scroll = ttk.Scrollbar(files_frame,orient='vertical',command=self.tree.yview)
        scroll.pack(side='right',fill='y')
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind('<<TreeviewSelect>>',self.selected)
        tool_bar = ttk.Frame(frame)
        tool_bar.pack(fill='x',pady=7)
        self.tool = tk.StringVar(value='Arquivos')
        ttk.Label(tool_bar,text='Abrir seleção em').pack(side='left',padx=(0,8))
        ttk.Combobox(tool_bar,textvariable=self.tool,state='readonly',width=23,values=[
            'Capturas','Arquivos','Logs','John · hashes','John · wordlist','Hydra · wordlist']).pack(side='left')
        tool = ttk.Button(tool_bar,text='Usar arquivo na ferramenta',style='CtfRun.TButton',command=self.send_file)
        tool.pack(side='left',padx=8)
        ttk.Button(tool_bar,text='Ver comandos de preparação',style='CtfInfo.TButton',command=self.commands).pack(side='left')
        HoverTip(tool,'Encaminha o arquivo selecionado para a ferramenta escolhida no Cyberpm.')
        self.document = ScrolledText(frame,height=12,wrap='word',state='disabled')
        self.document.tag_configure('flag', foreground='#103d23', background='#baf3cb',
                                    font=('TkFixedFont', 13, 'bold'), spacing1=5, spacing3=5)
        self.document.pack(fill='both',expand=True,pady=6)
        url_bar = ttk.Frame(frame)
        url_bar.pack(fill='x')
        self.url = tk.StringVar()
        ttk.Label(url_bar,text='URL do laboratório').pack(side='left',padx=(0,7))
        ttk.Entry(url_bar,textvariable=self.url).pack(side='left',fill='x',expand=True)
        ttk.Button(url_bar,text='Abrir URL / importar flags',style='CtfRun.TButton',command=self.send_url).pack(side='left',padx=7)
        self.poll_id = self.after(100,self.poll)
        self.protocol('WM_DELETE_WINDOW',self.close)
        self.bind('<Destroy>',self.on_destroy,add='+')

    def browse_file(self):
        path = filedialog.askopenfilename(parent=self,title='Escolha uma evidência ou pacote ZIP')
        if path:
            self.source.set(path)

    def browse_folder(self):
        path = filedialog.askdirectory(parent=self,title='Escolha a pasta do laboratório')
        if path:
            self.source.set(path)

    def start(self):
        if self.busy:
            return
        if is_ctf_lab_url(self.source.get()):
            self.url.set(self.source.get().strip())
            self.start_ctf_lab_import()
            return
        try:
            source = Path(self.source.get()).expanduser().resolve(strict=True)
            if not self.source.get().strip():
                raise ValueError('Selecione um arquivo ou pasta.')
            limit = int(self.limit.get())
            if limit<=0:
                raise ValueError('Informe um limite positivo em MiB.')
        except (OSError,ValueError) as exc:
            messagebox.showerror('Confira a origem',str(exc),parent=self)
            return
        self.busy = True
        self.stop.clear()
        self.import_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Importando arquivos…')
        def worker():
            try:
                if source.is_dir() or zipfile.is_zipfile(source):
                    info = import_package(source,limit_mib=limit,stop=self.stop)
                else:
                    info = {'root':source.parent,'title':source.name,'description':'Evidência individual selecionada.',
                            'instructions':'Escolha a ferramenta e clique em Usar arquivo na ferramenta.',
                            'readme':'','url':'','setup':[],'files':[source]}
                self.events.put(('ready',info))
            except (OSError,ValueError,zipfile.BadZipFile,RuntimeError) as exc:
                self.events.put(('error',str(exc)))
        threading.Thread(target=worker,daemon=True).start()

    def start_ctf_lab_import(self):
        if self.busy:
            return
        self.busy = True
        self.stop.clear()
        self.import_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Carregando o catálogo de resultados do CTF Lab…')

        def worker():
            try:
                results = import_ctf_lab_results()
                if self.stop.is_set():
                    raise InterruptedError('Importação interrompida.')
                self.events.put(('flags', results))
            except (OSError, ValueError) as exc:
                self.events.put(('error', str(exc)))

        threading.Thread(target=worker,daemon=True).start()

    def display_ctf_lab_results(self, results):
        self.info = None
        self.files.clear()
        self.tree.delete(*self.tree.get_children())
        self.document.configure(state='normal')
        self.document.delete('1.0','end')
        self.document.insert('end', 'CTF Lab · Respostas publicadas pelo laboratório\n\n')
        for result in results:
            self.document.insert('end', f"{result['title']} · {result['category']}\n")
            self.document.insert('end', f"FLAG  {result['flag']}\n", 'flag')
            self.document.insert('end', result['explanation']+'\n\n')
        self.document.configure(state='disabled')
        self.document.see('1.0')
        self.status.set(f"{len(results)} flags importadas. Consulte os resultados destacados abaixo.")

    def display(self, info):
        self.info = info
        self.tree.delete(*self.tree.get_children())
        self.files = {}
        for index,path in enumerate(info['files']):
            key = str(index)
            self.files[key] = path
            try:
                name = str(path.relative_to(info['root']))
            except ValueError:
                name = path.name
            self.tree.insert('', 'end',iid=key,text=name,values=(path.stat().st_size,))
        text = info['title']+'\n\n'+info['description']+'\n\n'+info['instructions']
        if info['readme']:
            text += '\n\nENUNCIADO / README\n'+info['readme']
        text += '\n\nPasta do laboratório\n'+str(info['root'])
        self.document.configure(state='normal')
        self.document.delete('1.0','end')
        self.document.insert('end',text)
        self.document.configure(state='disabled')
        self.url.set(info['url'])
        if self.files:
            self.tree.selection_set(next(iter(self.files)))
            self.selected()
        self.status.set(f'{len(self.files)} arquivos disponíveis. Consulte a preparação antes de iniciar o laboratório.')

    def selected(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        path = self.files[selection[0]]
        name = path.name.lower()
        if path.suffix.lower() in ('.pcap','.pcapng','.cap'):
            self.tool.set('Capturas')
        elif path.suffix.lower()=='.log':
            self.tool.set('Logs')
        elif 'hash' in name:
            self.tool.set('John · hashes')
        elif any(word in name for word in ('wordlist','palavras','senhas')):
            self.tool.set('John · wordlist')
        else:
            self.tool.set('Arquivos')

    def send_file(self):
        selection = self.tree.selection()
        if not selection:
            self.status.set('Selecione um arquivo da lista primeiro.')
            return
        self.open_file(self.tool.get(),str(self.files[selection[0]]))

    def send_url(self):
        if is_ctf_lab_url(self.url.get()):
            self.start_ctf_lab_import()
            return
        try:
            url = target_url(self.url.get())
        except ValueError as exc:
            messagebox.showerror('URL inválida',str(exc),parent=self)
            return
        self.use_url(url)

    def commands(self):
        if self.info is None:
            self.status.set('Importe o pacote ou selecione uma pasta primeiro.')
            return
        text = shell_command(['cd',str(self.info['root'])])+'\n'
        text += '\n'.join(self.info['setup']) if self.info['setup'] else '# Consulte o README acima para preparar este laboratório.'
        show_document(self,'Preparação do laboratório','Leia o README e os comandos de preparação. '
                      'Copie para o terminal quando quiser iniciar o laboratório.',text)

    def template(self):
        path = filedialog.asksaveasfilename(parent=self,defaultextension='.zip',initialfile='ctf-modelo.zip')
        if not path:
            return
        try:
            write_template(path)
        except OSError as exc:
            messagebox.showerror('Pacote modelo',str(exc),parent=self)
            return
        self.source.set(path)
        self.status.set('Modelo salvo. Clique em Importar / abrir para testar o formato.')

    def poll(self):
        for _ in range(20):
            try:
                kind,value = self.events.get_nowait()
            except queue.Empty:
                break
            self.busy = False
            self.import_button.configure(state='normal')
            self.stop_button.configure(state='disabled')
            if kind=='ready':
                self.display(value)
            elif kind=='flags':
                self.display_ctf_lab_results(value)
            else:
                self.status.set('Falha na importação: '+value)
        self.poll_id = self.after(100,self.poll)

    def on_destroy(self, event):
        if event.widget is self:
            self.stop.set()
            self.after_cancel(self.poll_id)

    def close(self):
        self.stop.set()
        if self.busy:
            self.status.set('Interrompendo a importação…')
            self.after(100,self.close)
            return
        self.destroy()
