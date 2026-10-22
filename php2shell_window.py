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
from php2shell import HttpClient, Response, exploit_used, headline, scan, to_rows

ROUTE_MISS = (404, 405, 410)
STRONG_ACTIVE = ('rce_hit', 'armed', 'session_fixation', 'crash_signal')


class WindowClient(HttpClient):
    def __init__(self, url, stop, progress=None, budget=90):
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
            return Response(url=url, error='interrompido' if self.stop.is_set() else 'limite de tempo atingido')
        if target_origin(url) != self.origin:
            self.partial = True
            return Response(url=url, error='URL fora da origem selecionada')
        self.timeout = min(8, remaining)
        if self.progress:
            self.progress(f'{method} {url}')
        response = super().request(method, url, data=data, headers=headers)
        self.responses.append({'method': method, 'url': url, 'status': response.status, 'error': response.error})
        if response.error and response.status not in ROUTE_MISS:
            self.partial = True
        return response


def _parse_call(value):
    value = (value or '').strip()
    if not value:
        return 0
    try:
        return int(value, 0)
    except ValueError:
        return int(value, 16)


def scan_target(url, stop, deep=True, progress=None, active=True,
                chain='618', call=0, command='id', stall=1.2, max_paths=2,
                progress_path=None):
    url = normalize_target(url)
    client = WindowClient(url, stop, progress)
    finding = scan(url, timeout=8, deep=deep, verify_tls=True, client=client,
                   active=active or chain == '619', chain=chain, call_addr=call,
                   command=command, stall=stall, max_paths=max_paths,
                   progress_path=progress_path, stop=stop.is_set,
                   deadline=client.deadline)
    finding['partial'] = client.partial or stop.is_set()
    finding['mode'] = 'fingerprint + upload_progress' if deep else 'fingerprint'
    if active or chain == '619':
        finding['mode'] += ' + teste ativo'
    finding['http_responses'] = client.responses
    for attempt in (finding.get('active') or {}).get('attempts', []):
        if attempt.get('transport') == 'socket':
            finding['http_responses'].append({
                'method': 'POST', 'url': attempt['url'], 'status': attempt['status'],
                'error': attempt.get('error', ''),
            })
    return finding


def conclusion(finding):
    responses = finding.get('http_responses') or []
    statuses = [row.get('status') for row in responses if row.get('status')]
    answered = list(statuses)
    active = finding.get('active') or {}
    strong = active.get('status') in STRONG_ACTIVE
    verdict = finding.get('verdict', 'UNKNOWN')

    if statuses and all(status in (401, 403, 429) for status in statuses) and not strong:
        codes = ', '.join(str(code) for code in sorted(set(statuses)))
        return ('INCONCLUSIVO', f'O servidor recusou ou limitou as requisições (HTTP {codes}). Não foi possível determinar se a vulnerabilidade existe.',
                'Confirme com o administrador uma URL PHP acessível e as condições de acesso autorizadas.')

    if statuses and all(status == 404 for status in statuses) and not strong:
        return ('INCONCLUSIVO', 'Todas as rotas testadas devolveram 404: a aplicação não responde nos caminhos convencionais.',
                'Informe a URL exata de uma página PHP que exista e repita o scan.')

    if verdict == 'RCE_CONFIRMED':
        return ('EXECUÇÃO DE CÓDIGO CONFIRMADA', 'O marcador do comando voltou no corpo da resposta após a cadeia 619.',
                'Confirme o usuário do processo e rotacione segredos.')

    if verdict == 'PRIMITIVE_CONFIRMED':
        return ('PRIMITIVA CONFIRMADA', 'O alvo respondeu ao teste ativo (fixação de sessão ou monitor de upload_progress). A superfície do CVE está viva.',
                'Preserve os logs do PHP-FPM e aplique a correção.')

    if verdict == 'CRASH_SIGNAL':
        return ('INDÍCIO FORTE — WORKER INSTÁVEL', 'O worker não respondeu ao multipart em duas fases (502/503/504 ou 0 bytes).',
                'Verifique segfaults no log do FPM e confirme a versão instalada.')

    if verdict == 'PATCHED' and (not finding.get('partial') or answered):
        return ('CORREÇÃO INDICADA PELA VERSÃO', 'A versão anunciada está na faixa corrigida. Não comprova que toda a aplicação está segura.',
                'Confirme a versão e o pacote realmente instalados.')

    if verdict == 'VULNERABLE':
        return ('INDÍCIOS DE EXPOSIÇÃO', 'Versão considerada afetada e sinais de upload_progress.',
                'Valide versão e configuração com o administrador.')

    if verdict in ('LIKELY_VULNERABLE', 'EOL_VULNERABLE'):
        return ('POTENCIALMENTE AFETADO', 'Sinais compatíveis com versão afetada ou sem suporte.',
                'Confirme o pacote instalado e a configuração efetiva do PHP.')

    return ('INCONCLUSIVO', 'Não há evidência suficiente para responder sim ou não.',
            'Solicite ao administrador a versão real do PHP e uma rota de teste acessível.')


def format_result(finding):
    label, reason, next_step = conclusion(finding)
    head, head_reason, head_action = headline(finding)
    lines = [
        f'CONCLUSÃO: {label}',
        f'VEREDITO: {head}',
        f'Alvo: {finding.get("target")}',
        f'PHP: {finding.get("php_version") or "não exposta (expose_php=Off)"}',
        f'CVE: {", ".join(finding.get("cve", []))} · CVSS {finding.get("cvss", "")}',
        f'Motivo: {reason}',
        f'Por quê: {head_reason}',
        f'Próximo passo: {head_action}',
        '',
        'EXPLOIT USADO:',
    ]
    for line in exploit_used(finding):
        lines.append('  - ' + line)
    lines.append('')
    lines.append('Detalhes técnicos:')
    lines.extend(f'{name}: {value}' for name, value in to_rows(finding))
    active = finding.get('active') or {}
    if active:
        lines.append(f"Sinal do teste ativo: {active.get('status')} "
                     f"(sondas {', '.join(active.get('variants', []))}, "
                     f"{active.get('requests', 0)} requisição(ões), "
                     f"pontuação {active.get('best_score', 0)})")
        if active.get('chain_fallback'):
            lines.append('Cadeia 619 pedida sem offset: as sondas 618 rodaram no lugar.')
    lines.append('Cobertura: ' + ('parcial/inconclusiva' if finding.get('partial') else 'coleta encerrada'))
    lines.extend(f'Observação: {note}' for note in finding.get('notes', []))
    lines.append('Evidências:')
    lines.extend('  ' + str(item) for item in finding.get('evidence', []))
    for row in finding.get('http_responses', []):
        lines.append(f"  {row['method']} {row['url']} → HTTP {row['status'] or 'sem resposta'}"
                     + (f" ({row['error']})" if row.get('error') else ''))
    return '\n'.join(lines) + '\n'


def open_window(parent, initial_target=''):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    window = tk.Toplevel(parent)
    window.title('Scan PHP — php2shell')
    window.geometry('1080x800')
    frame = ttk.Frame(window, padding=12)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='Scan PHP — php2shell (CVE-2026-109618 / CVE-2026-109619)').pack(anchor='w')
    ttk.Label(frame, text='Uma URL por linha (até 50). Tudo já vem ligado: versão, oráculo e exploit. TLS validado, sem redirecionamentos.',
              wraplength=1020).pack(anchor='w', pady=5)
    targets = tk.Text(frame, height=5, exportselection=False)
    targets.pack(fill='x')
    if initial_target:
        targets.insert('1.0', initial_target)

    deep = tk.BooleanVar(value=True)
    option = ttk.Checkbutton(frame, text='Oráculo upload_progress (POST multipart)',
                             variable=deep)
    option.pack(anchor='w', pady=(5, 0))
    active = tk.BooleanVar(value=True)
    option_active = ttk.Checkbutton(
        frame, text='Teste ativo + exploit: stall multipart em duas fases e sonda de fixação de sessão',
        variable=active)
    option_active.pack(anchor='w')

    advanced = ttk.Frame(frame)
    advanced.pack(fill='x', pady=(2, 5))
    ttk.Label(advanced, text='RCE 619 (opcional) — call em hex:').pack(side='left')
    call_entry = ttk.Entry(advanced, width=16)
    call_entry.pack(side='left', padx=(4, 8))
    ttk.Label(advanced, text='comando (≤14B):').pack(side='left')
    command_entry = ttk.Entry(advanced, width=18)
    command_entry.insert(0, 'id')
    command_entry.pack(side='left', padx=4)
    ttk.Label(advanced, text='(call vazio = roda só as sondas 618)').pack(side='left')

    controls = ttk.Frame(frame)
    controls.pack(fill='x', pady=6)
    status = tk.StringVar(value='Pronto. Nenhum scan iniciado.')
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

    def worker(urls, active_probe, call_hex, command):
        try:
            for index, url in enumerate(urls, 1):
                if stop.is_set():
                    break
                messages.put(('log', f'[{index}/{len(urls)}] {url}'))
                try:
                    finding = scan_target(
                        url, stop, deep=deep.get(),
                        progress=lambda text: messages.put(('log', text)),
                        active=active_probe,
                        chain='619' if call_hex else '618',
                        call=_parse_call(call_hex),
                        command=command,
                    )
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
            urls = list(dict.fromkeys(normalize_target(line)
                                      for line in targets.get('1.0', 'end').splitlines()
                                      if line.strip()))
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
        call_hex = call_entry.get().strip()
        command = command_entry.get().strip() or 'id'
        append(f'Alvos: {len(urls)}')
        append(f'Modo: versão + oráculo + {"cadeia 619" if call_hex else "sondas 618 (stall, micro, fixação)"}')
        append('')
        start_button.configure(state='disabled')
        stop_button.configure(state='normal')
        for widget in (targets, option, option_active, call_entry, command_entry):
            widget.configure(state='disabled')
        status.set('Executando Scan PHP…')
        threading.Thread(target=worker, args=(urls, active.get(), call_hex, command),
                         daemon=True).start()

    def cancel():
        stop.set()
        status.set('Parando após a requisição atual (timeout de até 8s)…')

    def export():
        if not results:
            messagebox.showinfo('Exportar', 'Nenhum resultado coletado.', parent=window)
            return
        name = filedialog.asksaveasfilename(parent=window, defaultextension='.json',
                                            initialfile='php2shell.json',
                                            filetypes=[('JSON', '*.json')])
        if name:
            try:
                with open(name, 'w', encoding='utf-8') as stream:
                    json.dump({'module': 'php2shell',
                               'partial': running or stop.is_set() or any(row.get('partial') for row in results),
                               'results': results}, stream, ensure_ascii=False, indent=2)
            except OSError as exc:
                messagebox.showerror('Exportar', str(exc), parent=window)

    def copy(event=None):
        try:
            selected = bool(event is not None and output.tag_ranges('sel'))
            text = output.get('sel.first', 'sel.last') if selected else output.get('1.0', 'end-1c')
            if not text:
                status.set('Não há resultado para copiar.')
                return 'break'
            write_text(window, text)
            status.set(f'{len(text)} caracteres copiados para a área de transferência.')
        except (tk.TclError, OSError) as exc:
            messagebox.showerror('Copiar resultados',
                                 f'Não foi possível acessar a área de transferência: {exc}',
                                 parent=window)
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
                append(format_result(data) if kind == 'result'
                       else f"Falha em {data['target']}: {data['error']}")
            elif kind == 'done':
                running = False
                start_button.configure(state='normal')
                stop_button.configure(state='disabled')
                for widget in (targets, option, option_active, call_entry, command_entry):
                    widget.configure(state='normal')
                vuln = sum(1 for row in results
                           if 'error' not in row and (row.get('headline') or '').startswith('VULNER'))
                inconclusive = any('error' in row or (row.get('headline') or '').startswith('INCONCLUSIVO')
                                   for row in results)
                label = ('Interrompido' if stop.is_set()
                         else f'{vuln} VULNERÁVEL(is) em {len(results)}' if vuln
                         else 'Executado — resultado inconclusivo' if inconclusive
                         else 'Executado')
                status.set(f'{label}.')
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