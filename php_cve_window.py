"""Dedicated PHP CVE triage window, independent of audit phases."""
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from php_cve_check import check_url, normalize_target, SOURCE, LIMITATION


def open_window(parent):
    window = tk.Toplevel(parent)
    window.title('PHP — CVE-2026-109618 / CVE-2026-109619')
    window.geometry('1000x700')
    frame = ttk.Frame(window, padding=12)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='Scan PHP independente — uma URL por linha').pack(anchor='w')
    ttk.Label(frame, text='Triagem por cabeçalhos HTTP (HEAD). Não confirma vulnerabilidade nem executa exploração.', wraplength=930).pack(anchor='w', pady=5)
    targets = tk.Text(frame, height=6, exportselection=False)
    targets.pack(fill='x')
    controls = ttk.Frame(frame); controls.pack(fill='x', pady=8)
    status = tk.StringVar(value='Pronto. Limite de 50 URLs por execução; até 10s por URL.')
    ttk.Label(frame, textvariable=status).pack(anchor='w')
    output = tk.Text(frame, wrap='word', exportselection=False)
    scroll = ttk.Scrollbar(frame, command=output.yview)
    scroll.pack(side='right', fill='y')
    output.configure(yscrollcommand=scroll.set)
    output.pack(fill='both', expand=True)
    output.configure(state='disabled')
    messages = queue.Queue()
    stop = threading.Event()
    results = []
    running = False

    def append(text):
        output.configure(state='normal'); output.insert('end', text+'\n'); output.see('end'); output.configure(state='disabled')

    def worker(urls):
        try:
            for index, url in enumerate(urls, 1):
                if stop.is_set(): break
                messages.put(('log', f'[{index}/{len(urls)}] HEAD {url}'))
                messages.put(('result', check_url(url)))
        except Exception as exc:
            messages.put(('log', f'Erro: {exc}'))
        finally:
            messages.put(('done', None))

    def start():
        nonlocal running
        if running: return
        try:
            urls = list(dict.fromkeys(normalize_target(line) for line in targets.get('1.0','end').splitlines() if line.strip()))
            if not urls or len(urls)>50: raise ValueError('Informe de 1 a 50 URLs.')
        except ValueError as exc:
            messagebox.showwarning('URLs', str(exc), parent=window); return
        results.clear(); stop.clear(); running=True
        output.configure(state='normal'); output.delete('1.0','end'); output.configure(state='disabled')
        append('Escopo: CVE-2026-109618 e CVE-2026-109619\nFonte: '+SOURCE+'\n'+LIMITATION)
        start_button.configure(state='disabled'); stop_button.configure(state='normal'); targets.configure(state='disabled')
        status.set('Executando triagem PHP...')
        threading.Thread(target=worker, args=(urls,), daemon=True).start()

    def cancel():
        stop.set(); status.set('Parando após a requisição atual (até 10s)...')

    def save():
        if not results:
            messagebox.showinfo('Exportar', 'Nenhum resultado coletado.', parent=window); return
        name=filedialog.asksaveasfilename(parent=window, defaultextension='.json', initialfile='php-cves.json', filetypes=[('JSON','*.json')])
        if name:
            try:
                with open(name,'w',encoding='utf-8') as stream:
                    json.dump({'cves':['CVE-2026-109618','CVE-2026-109619'], 'partial':running or stop.is_set(), 'results':results}, stream, ensure_ascii=False, indent=2)
            except OSError as exc:
                messagebox.showerror('Exportar', str(exc), parent=window)

    def copy():
        parent.clipboard_clear(); parent.clipboard_append(output.get('1.0','end-1c'))

    def poll():
        nonlocal running
        if not window.winfo_exists(): return
        while True:
            try: kind, data = messages.get_nowait()
            except queue.Empty: break
            if kind=='log': append(data)
            elif kind=='result':
                results.append(data)
                append(f"{data['status']} | HTTP {data['http_status']} | PHP {data['version'] or 'oculto'}\n{data['url']}\n{data['detail']}\n")
            elif kind=='done':
                running=False
                start_button.configure(state='normal'); stop_button.configure(state='disabled'); targets.configure(state='normal')
                status.set(('Interrompido' if stop.is_set() else 'Concluído')+f': {len(results)} resultado(s).')
        window.after(100, poll)

    def close():
        stop.set(); window.destroy()

    start_button=ttk.Button(controls, text='Iniciar scan PHP', command=start); start_button.pack(side='left')
    stop_button=ttk.Button(controls, text='Parar', command=cancel, state='disabled'); stop_button.pack(side='left', padx=6)
    ttk.Button(controls, text='Exportar JSON', command=save).pack(side='left')
    ttk.Button(controls, text='Copiar resultados', command=copy).pack(side='left', padx=6)
    window.protocol('WM_DELETE_WINDOW', close)
    window.after(100,poll)
    return window
