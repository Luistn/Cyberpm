"""Shodan IP lookup and search, with an in-memory API key."""
import ipaddress
import json
import queue
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def search_query(query='', country='', state='', city=''):
    country = country.strip().upper()
    if country and not re.fullmatch(r'[A-Z]{2}', country):
        raise ValueError('Pais: informe o codigo de duas letras, como BR, US ou PT.')
    parts = [query.strip()] if query.strip() else []
    if country:
        parts.append('country:' + country)
    for name, value in (('state', state), ('city', city)):
        if value.strip():
            parts.append(name + ':' + json.dumps(value.strip(), ensure_ascii=False))
    if not parts:
        raise ValueError('Informe uma pesquisa ou um filtro geografico.')
    return ' '.join(parts)


def lookup(mode, value, key='', country='', state='', city=''):
    key = key.strip()
    if mode == 'IP':
        try:
            address = str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValueError('Informe um endereco IP. Para dominios, use a pesquisa com hostname:dominio.')
        url = ('https://api.shodan.io/shodan/host/' + address + '?' + urlencode({'key': key})
               if key else 'https://internetdb.shodan.io/' + address)
    elif mode == 'Pesquisa':
        if not key:
            raise ValueError('Pesquisa requer sua chave de API Shodan e acesso compativel com a conta.')
        query = search_query(value, country, state, city)
        url = 'https://api.shodan.io/shodan/host/search?' + urlencode({'key': key, 'query': query, 'page': 1})
    else:
        raise ValueError('Modo de consulta invalido.')
    try:
        with urlopen(Request(url, headers={'User-Agent': 'Cyberpm-Shodan'}), timeout=20) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('Resposta grande demais. Refine os filtros.')
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('Resposta Shodan invalida.')
        if key:
            # Never display or export a key, even if a remote error echoes it.
            data = json.loads(json.dumps(data).replace(key, '[chave removida]'))
        return data
    except HTTPError as exc:
        messages = {401: 'Chave de API recusada.', 403: 'A conta nao permite esta consulta ou nao possui creditos.',
                    404: 'Nenhum registro encontrado.', 429: 'Limite de consultas atingido. Aguarde.'}
        raise ValueError(messages.get(exc.code, f'Shodan respondeu HTTP {exc.code}.')) from None
    except (URLError, OSError, TimeoutError):
        raise ValueError('Falha de conexao com o Shodan. Verifique rede e TLS.') from None


class ShodanWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('Shodan - IP, pais e estado')
        self.geometry('920x700')
        self.minsize(700, 540)
        self.mode = tk.StringVar(value='IP')
        self.value = tk.StringVar()
        self.key = tk.StringVar()
        self.country = tk.StringVar()
        self.state = tk.StringVar()
        self.city = tk.StringVar()
        self.status = tk.StringVar(value='IP sem chave usa InternetDB; pesquisa requer chave Shodan.')
        self.events = queue.Queue()
        self.busy = False
        self.data = None
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1)
        self.controls = []
        for row, label, variable in ((0, 'IP ou consulta Shodan', self.value), (1, 'Chave API (nao salva)', self.key),
                                     (2, 'Pais (BR, US, PT...)', self.country), (3, 'Estado / regiao', self.state),
                                     (4, 'Cidade', self.city)):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=(0, 8))
            entry = ttk.Entry(frame, textvariable=variable, show='*' if variable is self.key else '')
            entry.grid(row=row, column=1, sticky='ew', pady=4)
            self.controls.append(entry)
        self.mode_box = ttk.Combobox(frame, textvariable=self.mode, values=('IP', 'Pesquisa'), state='readonly')
        self.mode_box.grid(row=5, column=1, sticky='ew', pady=4)
        ttk.Label(frame, text='Modo').grid(row=5, column=0, sticky='w')
        self.mode_box.bind('<<ComboboxSelected>>', lambda event: self.update_filters())
        for variable in (self.country, self.state, self.city):
            variable.trace_add('write', lambda *args: self.preview())
        ttk.Label(frame, text='Exemplo de pesquisa: hostname:example.org. Filtros geograficos valem no modo Pesquisa.\n'
                  'Resultados sao registros do Shodan; CVEs listadas precisam de validacao. Pesquisa exibe a primeira pagina.',
                  wraplength=800).grid(row=6, column=0, columnspan=2, sticky='w', pady=6)
        self.query_preview = tk.StringVar()
        ttk.Label(frame, textvariable=self.query_preview, wraplength=800).grid(row=7, column=0, columnspan=2, sticky='w')
        bar = ttk.Frame(frame)
        bar.grid(row=8, column=0, columnspan=2, sticky='ew', pady=8)
        self.search_button = ttk.Button(bar, text='Consultar Shodan', style='Start.TButton', command=self.search)
        self.search_button.pack(side='left')
        ttk.Button(bar, text='Exportar JSON', style='Accent.TButton', command=self.export).pack(side='left', padx=6)
        self.output = ScrolledText(frame, state='disabled', wrap='word')
        self.output.grid(row=9, column=0, columnspan=2, sticky='nsew')
        frame.rowconfigure(9, weight=1)
        ttk.Label(frame, textvariable=self.status, wraplength=800).grid(row=10, column=0, columnspan=2, sticky='w', pady=6)
        self.update_filters()
        self.poll_id = self.after(100, self.poll)
        self.protocol('WM_DELETE_WINDOW', self.close)

    def preview(self):
        try:
            value = search_query(self.value.get(), self.country.get(), self.state.get(), self.city.get())
        except ValueError as exc:
            value = str(exc)
        self.query_preview.set('Pesquisa: ' + value if self.mode.get() == 'Pesquisa' else '')

    def update_filters(self):
        for entry in self.controls[2:]:
            entry.configure(state='normal' if self.mode.get() == 'Pesquisa' and not self.busy else 'disabled')
        self.preview()

    def search(self):
        if self.busy:
            return
        args = (self.mode.get(), self.value.get(), self.key.get(), self.country.get(), self.state.get(), self.city.get())
        self.busy = True
        self.search_button.configure(state='disabled')
        self.mode_box.configure(state='disabled')
        for entry in self.controls:
            entry.configure(state='disabled')
        self.data = None
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.configure(state='disabled')
        self.status.set('Consultando Shodan...')

        def worker():
            try:
                self.events.put(('data', lookup(*args)))
            except ValueError as exc:
                self.events.put(('error', str(exc)))
            except Exception:
                self.events.put(('error', 'Resposta indisponivel ou invalida.'))
        threading.Thread(target=worker, daemon=True).start()

    def export(self):
        if self.data is None:
            return messagebox.showinfo('Shodan', 'Execute uma consulta primeiro.', parent=self)
        path = filedialog.asksaveasfilename(parent=self, title='Exportar consulta Shodan', defaultextension='.json')
        if path:
            try:
                Path(path).write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding='utf-8')
            except OSError as exc:
                messagebox.showerror('Shodan', str(exc), parent=self)

    def poll(self):
        try:
            kind, value = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.search_button.configure(state='normal')
            self.mode_box.configure(state='readonly')
            for entry in self.controls:
                entry.configure(state='normal')
            self.update_filters()
            if kind == 'data':
                self.data = value
                self.output.configure(state='normal')
                self.output.insert('end', json.dumps(value, ensure_ascii=False, indent=2))
                self.output.configure(state='disabled')
                self.status.set('Consulta concluida. Total: ' + str(value.get('total', 'consulta de IP')))
            else:
                self.status.set(value)
        self.poll_id = self.after(100, self.poll)

    def close(self):
        self.after_cancel(self.poll_id)
        self.key.set('')
        self.destroy()
