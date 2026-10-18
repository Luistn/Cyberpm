"""Consultas públicas OSINT, sem coleta automática de dados pessoais."""
import json
import re
import queue
import threading
import tkinter as tk
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlencode
from osint_tools import availability, run_tools, install_missing
from urllib.parse import urlparse


def detect_kind(value):
    value = value.strip()
    if not value:
        return None
    if '@' in value:
        return 'Usuário' if value.startswith('@') and value.count('@') == 1 else 'E-mail'
    if re.fullmatch(r'[A-Za-z]{3}[ -]?\d(?:\d|[A-Za-z])\d{2}', value):
        return 'Placa'
    if re.fullmatch(r'\+?[\d\s().-]{8,}', value):
        return 'Telefone'
    if '://' in value or re.fullmatch(r'(?:[\w-]+\.)+[\w-]+(?::\d+)?(?:/\S*)?', value):
        return 'Domínio'
    return 'Nome'


def prepare_query(kind, value, context=''):
    value = ' '.join(value.split())
    context = ' '.join(context.split())
    if not value or len(value) > 200 or len(context) > 200:
        raise ValueError('Informe uma consulta de até 200 caracteres.')
    details = []
    if kind == 'Usuário':
        value = value.lstrip('@')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', value):
            raise ValueError('Informe um nome de usuário com até 64 letras, dígitos, pontos, traços ou sublinhados.')
        details.append('Busca de perfis públicos por apelido; correspondência não confirma identidade.')
    elif kind == 'Domínio':
        host = urlparse(value if '://' in value else 'https://' + value).hostname
        from osint_tools import email_domain
        if not host:
            raise ValueError('Informe um domínio válido.')
        value = email_domain('query@' + host)
        details.append('Consulta DNS/WHOIS do domínio; não executa varredura web.')
    elif kind == 'Nome':
        if len(value) < 3:
            raise ValueError('Informe um nome com pelo menos 3 caracteres.')
        details.append('Nome informado; homônimos precisam de verificação manual.')
    elif kind == 'Telefone':
        if not re.fullmatch(r'\+?[\d\s().-]+', value):
            raise ValueError('Use apenas dígitos, + inicial e separadores de telefone.')
        value = re.sub(r'[^\d+]', '', value)
        if not 8 <= len(value.lstrip('+')) <= 15:
            raise ValueError('O telefone deve conter entre 8 e 15 dígitos, incluindo DDI quando conhecido.')
        details.append('Formato plausível; não confirma linha ativa, operadora ou titular.')
    elif kind == 'E-mail':
        if not re.fullmatch(r'[^\s@"<>]+@[^\s@"<>]+\.[^\s@"<>]+', value):
            raise ValueError('Informe um e-mail válido, como nome@dominio.com.')
        local, domain = value.rsplit('@', 1)
        value = local + '@' + domain.lower()
        details.append('Formato plausível; não confirma existência, entrega ou titularidade.')
    elif kind == 'Placa':
        value = re.sub(r'[\s-]', '', value).upper()
        if not re.fullmatch(r'[A-Z]{3}(?:\d{4}|\d[A-Z]\d{2})', value):
            raise ValueError('Use uma placa brasileira no padrão ABC1234 ou ABC1D23.')
        details.append('Formato brasileiro válido; nenhum cadastro veicular foi consultado.')
        details.append('Dados de proprietário exigem integração com base autorizada, não configurada.')
    else:
        raise ValueError('Tipo de consulta desconhecido.')
    query = '"' + value.replace('"', '') + '"'
    if context:
        query += ' ' + context
    sources = [
        {'source': 'Google — referências públicas', 'url': 'https://www.google.com/search?' + urlencode({'q': query})},
        {'source': 'Bing — referências públicas', 'url': 'https://www.bing.com/search?' + urlencode({'q': query})},
    ]
    return {'type': kind, 'value': value, 'context': context,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'status': 'Buscas preparadas; fontes ainda não verificadas',
            'details': details, 'sources': sources, 'evidence': []}


class OsintTab(ttk.Frame):
    def __init__(self, parent, no_install=None, on_event=None):
        super().__init__(parent, padding=16)
        self.report = None
        self.history = []
        self.on_event = on_event or (lambda state, message: None)
        self.no_install = no_install or (lambda: False)
        self.tool_running = False
        self.tool_events = queue.Queue()
        self.kind = tk.StringVar(value='Nome')
        self.value = tk.StringVar()
        self.context = tk.StringVar()
        ttk.Label(self, text='Consulta OSINT', font=('', 16, 'bold')).pack(anchor='w')
        ttk.Label(self, text='Nome, @usuário, telefone, e-mail, placa ou domínio • fontes públicas • revisão manual').pack(anchor='w', pady=(4, 12))
        bar = ttk.Frame(self)
        bar.pack(fill='x')
        ttk.Combobox(bar, textvariable=self.kind, values=('Nome', 'Usuário', 'Telefone', 'E-mail', 'Placa', 'Domínio'), state='readonly', width=12).pack(side='left')
        entry = ttk.Entry(bar, textvariable=self.value)
        entry.pack(side='left', fill='x', expand=True, padx=8)
        entry.bind('<Return>', lambda event: self.search())
        ttk.Button(bar, text='Preparar busca', command=self.search).pack(side='left')
        ttk.Label(self, text='Contexto opcional (cidade, empresa ou termo para reduzir homônimos)').pack(anchor='w', pady=(12, 4))
        ttk.Entry(self, textvariable=self.context).pack(fill='x')
        self.status = tk.StringVar(value='Nenhuma consulta. A busca só é enviada ao provedor ao abrir a fonte.')
        ttk.Label(self, textvariable=self.status, wraplength=950).pack(anchor='w', pady=12)
        self.sources = ttk.Treeview(self, columns=('source', 'state'), show='headings', height=4)
        self.sources.heading('source', text='Fonte')
        self.sources.heading('state', text='Situação')
        self.sources.pack(fill='x')
        self.sources.bind('<Double-1>', lambda event: self.open_source())
        actions = ttk.Frame(self)
        actions.pack(fill='x', pady=8)
        ttk.Button(actions, text='Abrir fonte selecionada', command=self.open_source).pack(side='left')
        ttk.Button(actions, text='Exportar JSON', command=self.export).pack(side='left', padx=8)
        self.run_button = ttk.Button(actions, text='Executar ferramentas Kali', command=self.execute_tools)
        self.run_button.pack(side='left')
        deps = availability()
        ttk.Label(self, text='Dependências: ' + ' | '.join(name + (': disponível' if ok else ': ausente') for name, ok in deps.items())).pack(anchor='w')
        ttk.Label(self, text='Domínio: DNS/WHOIS/Subfinder. E-mail: DNS/WHOIS. @usuário: Sherlock. Telefone: metadados locais. Nome/placa: navegador.',wraplength=950).pack(anchor='w')
        self.tool_output = tk.Text(self, height=7, wrap='word', state='disabled')
        self.tool_output.pack(fill='x', pady=6)
        ttk.Label(self, text='Evidência: URL consultada e observação (possível correspondência, sem confirmação automática)').pack(anchor='w', pady=(12, 4))
        self.evidence_url = tk.StringVar()
        ttk.Entry(self, textvariable=self.evidence_url).pack(fill='x')
        self.note = tk.Text(self, height=6, wrap='word')
        self.note.pack(fill='both', expand=True, pady=6)
        ttk.Button(self, text='Registrar evidência', command=self.add_evidence).pack(anchor='w')
        self.count = tk.StringVar(value='0 evidências registradas')
        ttk.Label(self, textvariable=self.count).pack(anchor='w', pady=6)
        self.after(150, self.poll_tools)
        self.value.trace_add('write', self.detect_input)

    def detect_input(self, *_args):
        kind = detect_kind(self.value.get())
        if kind and not self.tool_running:
            self.kind.set(kind)
            self.on_event('Selecionada', 'Tipo identificado: ' + kind)

    def emit(self, state, message):
        self.on_event(state, message)

    def execute_tools(self, allow_install=None):
        if self.tool_running:
            return
        try:
            current = prepare_query(self.kind.get(), self.value.get(), self.context.get())
        except ValueError as exc:
            messagebox.showwarning('Ferramentas Kali', str(exc), parent=self)
            return
        if not self.report or any(current[key] != self.report[key] for key in ('type', 'value', 'context')):
            if not self.search():
                return
        self.tool_running = True
        self.emit('Executando', 'Início das ferramentas OSINT: ' + self.report['type'])
        self.run_button.configure(state='disabled')
        self.status.set('Instalando dependências ausentes e executando ferramentas. O Kali pode solicitar autenticação.')
        report = self.report
        allow_install = not self.no_install() if allow_install is None else allow_install
        def worker():
            try:
                records = install_missing(report['type']) if allow_install else []
                records += run_tools(report)
                self.tool_events.put((records, None))
            except Exception as exc:
                self.tool_events.put(([], str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def poll_tools(self):
        try:
            records, error = self.tool_events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.tool_running = False
            self.run_button.configure(state='normal')
            self.report.setdefault('tool_results', []).extend(records)
            self.tool_output.configure(state='normal')
            self.tool_output.delete('1.0', 'end')
            self.tool_output.insert('end', error or '\n\n'.join(
                f"{r['tool']} — {r['status']} — {r['collected_at']}\n{r['output']}" for r in records))
            self.tool_output.configure(state='disabled')
            self.status.set('Execução encerrada. Revise a situação de cada ferramenta abaixo.' if not error else 'Falha: ' + error)
            for record in records:
                self.emit('Executando', f"{record['tool']} — {record['status']}\n{record['output']}")
            partial = error or any(r['status'] != 'concluído' for r in records)
            self.emit('Falha/parcial' if partial else 'Concluída', error or 'Execução OSINT encerrada; revise os resultados.')
        self.after(150, self.poll_tools)

    def search(self, archive=False):
        if self.tool_running:
            messagebox.showinfo('Ferramentas Kali', 'Aguarde a execução atual antes de trocar a consulta.', parent=self)
            return
        try:
            report = prepare_query(self.kind.get(), self.value.get(), self.context.get())
        except ValueError as exc:
            messagebox.showwarning('Consulta OSINT', str(exc), parent=self)
            return
        if self.report and (self.report['evidence'] or self.report.get('tool_results')):
            if not archive and not messagebox.askyesno('Nova consulta', 'As evidências atuais ainda estão na memória. Iniciar outra consulta? Exporte antes se quiser guardá-las.', parent=self):
                return
            self.history.append(self.report)
        self.report = report
        self.emit('Preparada', 'Consulta OSINT preparada: ' + report['type'])
        self.tool_output.configure(state='normal')
        self.tool_output.delete('1.0', 'end')
        self.tool_output.configure(state='disabled')
        self.sources.delete(*self.sources.get_children())
        for i, source in enumerate(report['sources']):
            self.sources.insert('', 'end', iid=str(i), values=(source['source'], 'Busca preparada; não consultada'))
        self.status.set(' '.join(report['details']))
        self.count.set('0 evidências registradas')
        self.note.delete('1.0', 'end')
        self.evidence_url.set('')
        return True

    def open_source(self):
        selected = self.sources.selection()
        if not self.report or not selected:
            return
        source = self.report['sources'][int(selected[0])]
        try:
            if not webbrowser.open(source['url'], new=2):
                raise RuntimeError('Nenhum navegador respondeu.')
        except Exception as exc:
            messagebox.showwarning('Abrir fonte', str(exc), parent=self)
            return
        source['opened_at'] = datetime.now(timezone.utc).isoformat()
        self.emit('Revisão manual', 'Fonte aberta: ' + source['source'])
        self.sources.set(selected[0], 'state', 'Aberta no navegador; revisão pendente')

    def add_evidence(self):
        if not self.report:
            messagebox.showwarning('Evidência', 'Prepare uma consulta primeiro.', parent=self)
            return
        url = self.evidence_url.get().strip()
        note = self.note.get('1.0', 'end').strip()
        if not re.match(r'https?://[^\s]+$', url) or not note:
            messagebox.showwarning('Evidência', 'Informe uma URL HTTP(S) e uma observação.', parent=self)
            return
        item = {'url': url, 'note': note, 'recorded_at': datetime.now(timezone.utc).isoformat(),
                'confidence': 'Observação manual; correspondência não confirmada'}
        if any(e['url'] == url and e['note'] == note for e in self.report['evidence']):
            return
        self.report['evidence'].append(item)
        self.count.set(f"{len(self.report['evidence'])} evidências registradas")
        self.evidence_url.set('')
        self.note.delete('1.0', 'end')

    def export(self):
        if not self.report:
            messagebox.showinfo('Exportação', 'Prepare uma consulta primeiro.', parent=self)
            return
        dest = filedialog.asksaveasfilename(parent=self, defaultextension='.json', initialfile='consulta_osint.json', filetypes=[('JSON', '*.json')])
        if dest:
            try:
                data = dict(self.report)
                if self.history:
                    data['previous_queries'] = self.history
                Path(dest).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
            except OSError as exc:
                messagebox.showerror('Exportação', str(exc), parent=self)
