"""GUI adapter for the local php2shell detector; does not invoke external PoCs."""
import json
import queue
import ssl
import threading
import time
from urllib.request import HTTPSHandler, build_opener

from api_probe import NoRedirect
from system_clipboard import write_text
from audit_helpers import target_origin
from php_cve_check import normalize_target
from php2shell import HttpClient, Response, scan, to_rows


class WindowClient(HttpClient):
    def __init__(self, url, stop, progress=None, budget=60):
        super().__init__(timeout=8, verify_tls=True)
        self._opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        self.origin = target_origin(url)
        self.stop = stop
        self.progress = progress
        self.deadline = time.monotonic() + budget
        self.partial = False
        self.responses = []

    def request(self, method, url, data=None, headers=None):
        remaining = self.deadline - time.monotonic()
        if self.stop.is_set() or remaining <= 0:
            self.partial = True
            return Response(url=url, error='interrompido' if self.stop.is_set() else 'limite de 60s atingido')
        if target_origin(url) != self.origin:
            self.partial = True
            return Response(url=url, error='URL fora da origem selecionada')
        self.timeout = min(8, remaining)
        if self.progress:
            self.progress(f'{method} {url}')
        response = super().request(method, url, data=data, headers=headers)
        self.responses.append({'method': method, 'url': url, 'status': response.status, 'error': response.error})
        if response.error:
            self.partial = True
        return response


def scan_target(url, stop, deep=False, progress=None):
    url = normalize_target(url)
    client = WindowClient(url, stop, progress)
    finding = scan(url, timeout=8, deep=deep, verify_tls=True, client=client)
    finding['partial'] = client.partial or stop.is_set()
    finding['mode'] = 'fingerprint + upload_progress' if deep else 'fingerprint'
    finding['http_responses'] = client.responses
    return finding


def conclusion(finding):
    statuses = [row.get('status') for row in finding.get('http_responses', []) if row.get('status')]
    if statuses and all(status in (401, 403, 429) for status in statuses):
        codes = ', '.join(str(code) for code in sorted(set(statuses)))
        return ('INCONCLUSIVO', f'O servidor recusou ou limitou as requisições (HTTP {codes}). Não foi possível determinar se a vulnerabilidade existe.',
                'Confirme com o administrador uma URL PHP acessível e as condições de acesso autorizadas; confira a versão instalada no servidor.')
    verdict = finding.get('verdict', 'UNKNOWN')
    if verdict == 'PATCHED' and not finding.get('partial'):
        return ('CORREÇÃO INDICADA PELA VERSÃO', 'A versão anunciada está na faixa corrigida segundo a tabela do módulo. Isso não comprova que toda a aplicação está segura.',
                'Confirme a versão e o pacote realmente instalados com o administrador.')
    if verdict == 'VULNERABLE':
        return ('INDÍCIOS DE EXPOSIÇÃO', 'O módulo encontrou uma versão considerada afetada e sinais de upload_progress. O teste não comprovou execução de código.',
                'Valide versão, configuração e evidências com o administrador antes de confirmar a vulnerabilidade.')
    if verdict in ('LIKELY_VULNERABLE', 'EOL_VULNERABLE'):
        return ('POTENCIALMENTE AFETADO', 'O módulo encontrou sinais compatíveis com uma versão afetada ou sem suporte. A vulnerabilidade não foi confirmada.',
                'Confirme o pacote instalado, possíveis correções do fornecedor e a configuração efetiva do PHP.')
    return ('INCONCLUSIVO', 'Não há evidência suficiente para responder sim ou não. A versão pode estar oculta, o acesso pode ter sido recusado ou a coleta ficou parcial.',
            'Confira os códigos HTTP abaixo e solicite ao administrador a versão real do PHP e uma rota de teste acessível.')


def format_result(finding):
    label, reason, next_step = conclusion(finding)
    lines = [f'CONCLUSÃO: {label}', f'Alvo: {finding["target"]}', f'Motivo: {reason}', f'Próximo passo: {next_step}', '', 'Detalhes técnicos:']
    lines.extend(f'{"Veredito técnico do módulo" if label == "Veredito" else label}: {value}' for label, value in to_rows(finding))
    if finding.get('mode') == 'fingerprint':
        lines.append('Teste upload_progress: não executado (opção POST desmarcada).')
    lines.append('Cobertura: ' + ('parcial/inconclusiva' if finding.get('partial') else 'coleta encerrada'))
    lines.append('O veredito é produzido pelo módulo local; esta janela não confirma execução de código.')
    lines.extend(f'Observação: {note}' for note in finding.get('notes', []))
    lines.append('Evidências:')
    lines.extend('  ' + str(item) for item in finding.get('evidence', []))
    for row in finding.get('http_responses', []):
        lines.append(f"  {row['method']} {row['url']} → HTTP {row['status'] or 'sem resposta'}" + (f" ({row['error']})" if row.get('error') else ''))
    return '\n'.join(lines) + '\n'


def open_window(parent, initial_target=''):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    window = tk.Toplevel(parent)
    window.title('Scan PHP — php2shell')
    window.geometry('1050x720')
    frame = ttk.Frame(window, padding=12)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='Scan PHP — módulo php2shell.py da pasta atual').pack(anchor='w')
    ttk.Label(frame, text='Uma URL por linha (até 50). TLS validado, sem redirecionamentos; até 60s por URL.', wraplength=1000).pack(anchor='w', pady=5)
    targets = tk.Text(frame, height=5, exportselection=False)
    targets.pack(fill='x')
    if initial_target:
        targets.insert('1.0', initial_target)
    deep = tk.BooleanVar(value=False)
    option = ttk.Checkbutton(frame, text='Incluir teste leve de upload_progress (POST multipart)', variable=deep)
    option.pack(anchor='w', pady=5)
    controls = ttk.Frame(frame)
    controls.pack(fill='x', pady=6)
    status = tk.StringVar(value='Pronto. Fingerprint selecionado; nenhum scan iniciado.')
    ttk.Label(frame, textvariable=status).pack(anchor='w')
    output = tk.Text(frame, wrap='word', exportselection=False)
    scroll = ttk.Scrollbar(frame, command=output.yview)
    scroll.pack(side='right', fill='y')
    output.configure(yscrollcommand=scroll.set, state='disabled')
    output.pack(fill='both', expand=True)
    messages, stop, results = queue.Queue(), threading.Event(), []
    running = False

    def append(text):
        output.configure(state='normal')
        output.insert('end', text + '\n')
        output.see('end')
        output.configure(state='disabled')

    def worker(urls, active):
        try:
            for index, url in enumerate(urls, 1):
                if stop.is_set():
                    break
                messages.put(('log', f'[{index}/{len(urls)}] {url}'))
                try:
                    finding = scan_target(url, stop, deep=active, progress=lambda text: messages.put(('log', text)))
                    messages.put(('result', finding))
                except Exception as exc:
                    messages.put(('error', {'target': url, 'partial': True, 'error': str(exc)}))
        finally:
            messages.put(('done', None))

    def start():
        nonlocal running
        if running:
            return
        try:
            urls = list(dict.fromkeys(normalize_target(line) for line in targets.get('1.0', 'end').splitlines() if line.strip()))
            if not 1 <= len(urls) <= 50:
                raise ValueError('Informe de 1 a 50 URLs.')
        except ValueError as exc:
            messagebox.showwarning('Alvo', str(exc), parent=window)
            return
        running = True
        results.clear()
        stop.clear()
        output.configure(state='normal')
        output.delete('1.0', 'end')
        output.configure(state='disabled')
        start_button.configure(state='disabled')
        stop_button.configure(state='normal')
        targets.configure(state='disabled')
        option.configure(state='disabled')
        status.set('Executando Scan PHP…')
        threading.Thread(target=worker, args=(urls, deep.get()), daemon=True).start()

    def cancel():
        stop.set()
        status.set('Parando após a requisição atual (timeout de até 8s)…')

    def export():
        if not results:
            messagebox.showinfo('Exportar', 'Nenhum resultado coletado.', parent=window)
            return
        name = filedialog.asksaveasfilename(parent=window, defaultextension='.json', initialfile='php2shell.json', filetypes=[('JSON', '*.json')])
        if name:
            try:
                with open(name, 'w', encoding='utf-8') as stream:
                    json.dump({'module': 'php2shell', 'partial': running or stop.is_set() or any(row.get('partial') for row in results), 'results': results}, stream, ensure_ascii=False, indent=2)
            except OSError as exc:
                messagebox.showerror('Exportar', str(exc), parent=window)

    def copy(event=None):
        try:
            selected = bool(event is not None and output.tag_ranges('sel'))
            text = output.get('sel.first', 'sel.last') if selected else output.get('1.0', 'end-1c')
            if not text:
                status.set('Não há resultado para copiar.')
                return 'break'
            write_text(window,text)
            status.set(f'{len(text)} caracteres copiados para a área de transferência.')
        except (tk.TclError, OSError) as exc:
            messagebox.showerror('Copiar resultados', f'Não foi possível acessar a área de transferência: {exc}', parent=window)
        return 'break'

    def select_all(event=None):
        output.tag_add('sel', '1.0', 'end-1c')
        output.focus_set()
        return 'break'

    output.bind('<Control-c>', copy)
    output.bind('<Control-C>', copy)
    output.bind('<Control-a>', select_all)
    output.bind('<Control-A>', select_all)

    def poll():
        nonlocal running
        if not window.winfo_exists():
            return
        while True:
            try:
                kind, data = messages.get_nowait()
            except queue.Empty:
                break
            if kind == 'log':
                append(data)
            elif kind in ('result', 'error'):
                results.append(data)
                append(format_result(data) if kind == 'result' else f"Falha em {data['target']}: {data['error']}")
            elif kind == 'done':
                running = False
                start_button.configure(state='normal')
                stop_button.configure(state='disabled')
                targets.configure(state='normal')
                option.configure(state='normal')
                inconclusive = any('error' in row or conclusion(row)[0] == 'INCONCLUSIVO' for row in results)
                label = 'Interrompido' if stop.is_set() else 'Executado — resultado inconclusivo' if inconclusive else 'Executado com ressalvas' if any(row.get('partial') for row in results) else 'Executado'
                status.set(f'{label}: {len(results)} resultado(s).')
        window.after(100, poll)

    def close():
        stop.set()
        window.destroy()

    start_button = ttk.Button(controls, text='Iniciar Scan PHP', command=start)
    start_button.pack(side='left')
    stop_button = ttk.Button(controls, text='Parar', command=cancel, state='disabled')
    stop_button.pack(side='left', padx=6)
    ttk.Button(controls, text='Copiar resultados', command=copy).pack(side='left')
    ttk.Button(controls, text='Exportar JSON', command=export).pack(side='left', padx=6)
    window.protocol('WM_DELETE_WINDOW', close)
    window.after(100, poll)
    return window
