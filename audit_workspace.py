"""Native audit workspace: evidence review and contract-driven API checks."""
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from audit_helpers import api_kind, openapi_get_urls, target_host


def read_findings(folder):
    path = Path(folder) / 'achados.tsv'
    if not path.is_file(): return []
    if path.stat().st_size > 2000000:
        raise ValueError('Inventário muito grande; consulte o relatório completo.')
    rows = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines()[:5000]:
        parts = line.split('\t')
        if len(parts) < 5: continue
        severity, asset, category, message, evidence = parts[:5]
        identity = hashlib.sha256('\t'.join(parts[:5]).encode()).hexdigest()[:24]
        rows.append(dict(id=identity, severity=severity, asset=asset, category=category,
                         message=message, evidence=evidence))
    return rows


def save_review(folder, finding, status, reproduction, impact):
    if status not in ('A validar', 'Confirmado manualmente', 'Descartado'):
        raise ValueError('Estado de validação inválido.')
    if status != 'A validar' and not reproduction.strip():
        raise ValueError('Registre a reprodução ou o motivo do descarte.')
    if status == 'Confirmado manualmente' and not impact.strip():
        raise ValueError('Descreva o impacto observado antes de confirmar.')
    root = Path(folder).resolve()
    document = root / 'validacao_achados.json'
    reviews = json.loads(document.read_text(encoding='utf-8')) if document.exists() else {}
    if not isinstance(reviews, dict): raise ValueError('Arquivo de validação inválido.')
    receipt = {'status': status, 'reproduction': reproduction.strip(), 'impact': impact.strip(),
               'updated_at': datetime.now(timezone.utc).isoformat(), 'finding': finding}
    evidence = Path(finding['evidence'])
    if not evidence.is_absolute(): evidence = root / evidence
    evidence = evidence.resolve()
    if evidence.is_relative_to(root) and evidence.is_file() and evidence.stat().st_size <= 2000000:
        receipt['evidence_sha256'] = hashlib.sha256(evidence.read_bytes()).hexdigest()
    reviews[finding['id']] = receipt
    temp = document.with_suffix('.json.tmp')
    temp.write_text(json.dumps(reviews, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(document)
    return receipt


def load_contract(path, base):
    target_host(base)
    path = Path(path)
    if path.stat().st_size > 2000000: raise ValueError('Contrato excede 2 MB.')
    raw = path.read_text(encoding='utf-8-sig')
    if api_kind(raw) not in ('OpenAPI','Swagger'): raise ValueError('Selecione um contrato OpenAPI/Swagger JSON válido.')
    schema = json.loads(raw)
    urls = openapi_get_urls(base, schema)
    if not urls: raise ValueError('Nenhuma rota GET compatível na mesma origem, sem parâmetros obrigatórios.')
    return schema, urls


class AuditWorkspace(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=12)
        self.app = app
        self.folder = None
        self.rows = {}
        self.jobs = queue.Queue()
        self.process_lock=threading.Lock()
        self.cancel_requested=False
        self.summary = tk.StringVar(value='Nenhuma auditoria selecionada')
        self.review_status = tk.StringVar(value='A validar')
        self.api_path = tk.StringVar()
        self.api_status = tk.StringVar(value='Importe um contrato OpenAPI JSON e informe o site autorizado na aba Auditoria web.')
        ttk.Label(self, text='Central de auditoria', font=(app.F, 16, 'bold')).pack(anchor='w')
        ttk.Label(self, textvariable=self.summary).pack(anchor='w', pady=8)
        controls = ttk.Frame(self); controls.pack(fill='x')
        ttk.Button(controls, text='Atualizar evidências', command=self.refresh).pack(side='left')
        ttk.Button(controls, text='Abrir resultados anteriores', command=self.choose_folder).pack(side='left', padx=8)
        ttk.Button(controls, text='Gerar relatório', command=self.report).pack(side='left')
        tabs = ttk.Notebook(self); tabs.pack(fill='both', expand=True, pady=10)
        overview = ttk.Frame(tabs, padding=8); evidence = ttk.Frame(tabs, padding=8); api = ttk.Frame(tabs, padding=12)
        tabs.add(overview, text='Plano e execução atual'); tabs.add(evidence, text='Evidências e validação'); tabs.add(api, text='API por contrato')
        self.tasks = ttk.Treeview(overview, columns=('phase','state'), show='tree headings')
        self.tasks.heading('#0',text='Área'); self.tasks.heading('phase',text='Etapa'); self.tasks.heading('state',text='Situação')
        self.tasks.column('#0',width=160); self.tasks.column('phase',width=450); self.tasks.column('state',width=160)
        sb=ttk.Scrollbar(overview,orient='vertical',command=self.tasks.yview); sb.pack(side='right',fill='y'); self.tasks.configure(yscrollcommand=sb.set)
        self.tasks.pack(fill='both',expand=True)
        self.findings = ttk.Treeview(evidence, columns=('severity','category','message','state'), show='headings',height=6)
        for key, title, width in [('severity','Gravidade',100),('category','Categoria',170),('message','Achado',450),('state','Validação',170)]:
            self.findings.heading(key,text=title); self.findings.column(key,width=width)
        horizontal=ttk.Scrollbar(evidence,orient='horizontal',command=self.findings.xview); self.findings.configure(xscrollcommand=horizontal.set)
        self.findings.pack(fill='x'); horizontal.pack(fill='x')
        self.findings.bind('<<TreeviewSelect>>',self.select_finding)
        self.source=tk.StringVar(value='Selecione um achado para registrar a validação.')
        ttk.Label(evidence,textvariable=self.source,wraplength=850).pack(anchor='w',pady=4)
        ttk.Label(evidence,text='Reprodução / evidência observada / motivo do descarte').pack(anchor='w',pady=(8,2))
        self.reproduction=tk.Text(evidence,height=4,wrap='word',bg='#161b22',fg='#e6edf3',insertbackground='#58a6ff'); self.reproduction.pack(fill='both',expand=True)
        ttk.Label(evidence,text='Impacto observado').pack(anchor='w',pady=(8,2))
        self.impact=tk.Text(evidence,height=3,wrap='word',bg='#161b22',fg='#e6edf3',insertbackground='#58a6ff'); self.impact.pack(fill='both',expand=True)
        review=ttk.Frame(evidence); review.pack(fill='x',pady=8)
        ttk.Combobox(review,textvariable=self.review_status,values=('A validar','Confirmado manualmente','Descartado'),state='readonly',width=26).pack(side='left')
        ttk.Button(review,text='Salvar validação',command=self.review).pack(side='left',padx=8)
        ttk.Label(api,text='Testes GET/OPTIONS de rotas documentadas, dentro da origem do site. Comparação de sessão e validação de entradas inválidas.',wraplength=850).pack(anchor='w',pady=8)
        ttk.Entry(api,textvariable=self.api_path).pack(fill='x',pady=8)
        ttk.Button(api,text='Selecionar OpenAPI JSON',command=self.pick_contract).pack(anchor='w')
        self.api_button=ttk.Button(api,text='Testar contrato no site informado',command=self.run_contract,style='Accent.TButton'); self.api_button.pack(anchor='w',pady=12)
        ttk.Label(api,textvariable=self.api_status,wraplength=850).pack(anchor='w')
        self.after(300,self.tick)

    def choose_folder(self):
        folder=filedialog.askdirectory(parent=self,title='Pasta de resultados da auditoria')
        if folder: self.folder=folder; self.refresh()

    def active_folder(self):
        return self.folder or self.app.output_dir

    def refresh(self):
        folder=self.active_folder()
        if not folder: return
        try:
            rows=read_findings(folder)
            path=Path(folder)/'validacao_achados.json'
            reviews=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
            self.findings.delete(*self.findings.get_children()); self.rows={r['id']:r for r in rows}
            for row in rows:
                state=reviews.get(row['id'],{}).get('status','A validar')
                self.findings.insert('','end',iid=row['id'],values=(row['severity'],row['category'],row['message'],state))
            self.summary.set(f"{Path(folder).name} • {len(rows)} registros • evidências em {folder}")
        except (OSError,ValueError,TypeError) as exc: messagebox.showwarning('Evidências',str(exc),parent=self)

    def select_finding(self,_event=None):
        selected=self.findings.selection()
        if not selected: return
        finding=self.rows[selected[0]]
        path=Path(self.active_folder())/'validacao_achados.json'
        try: reviews=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
        except (OSError,ValueError): reviews={}
        review=reviews.get(finding['id'],{})
        self.source.set('Fonte: '+finding['evidence'])
        self.review_status.set(review.get('status','A validar'))
        self.reproduction.delete('1.0','end'); self.reproduction.insert('end',review.get('reproduction',''))
        self.impact.delete('1.0','end'); self.impact.insert('end',review.get('impact',''))

    def review(self):
        selected=self.findings.selection()
        if not selected: return
        try:
            save_review(self.active_folder(),self.rows[selected[0]],self.review_status.get(),self.reproduction.get('1.0','end'),self.impact.get('1.0','end'))
            self.findings.set(selected[0],'state',self.review_status.get())
        except (OSError,ValueError) as exc: messagebox.showwarning('Validação',str(exc),parent=self)

    def report(self):
        folder=self.active_folder()
        if not folder: return
        original=self.app.output_dir
        try: self.app.output_dir=folder; self.app.open_report()
        finally: self.app.output_dir=original

    def pick_contract(self):
        path=filedialog.askopenfilename(parent=self,filetypes=[('OpenAPI JSON','*.json')])
        if path: self.api_path.set(path)

    def run_contract(self):
        if self.app.running or getattr(self.app,'api_running',False) or self.app.brute_running:
            return messagebox.showinfo('Execução','Aguarde a execução atual.',parent=self)
        base=self.app.target.get().strip()
        if '://' not in base: base='https://'+base
        try:
            schema,urls=load_contract(self.api_path.get(),base)
            host=target_host(base)
            folder=Path(__file__).resolve().parent/'cyberpm-out'/host/'contratos'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            out=folder/'06_api'; out.mkdir(parents=True)
            (out/'openapi_import.body').write_text(json.dumps(schema,ensure_ascii=False),encoding='utf-8')
            (out/'rotas_get.txt').write_text('\n'.join(urls),encoding='utf-8')
        except (OSError,ValueError,TypeError) as exc:
            return messagebox.showwarning('Contrato API',str(exc),parent=self)
        env=os.environ.copy()
        mode={'HTTP Basic':'basic','Bearer':'bearer','Cookie':'cookie','Sessão do navegador':'cookie'}.get(self.app.auth_mode.get(),'none')
        env.update(AUTH_MODE=mode,AUTH_USER=self.app.auth_user.get(),AUTH_PASS=self.app.auth_pass.get(),AUTH_SECRET=self.app.session_cookie.get() if self.app.auth_mode.get()=='Sessão do navegador' else self.app.auth_secret.get())
        self.app.api_running=True; self.api_button.configure(state='disabled')
        self.app.stop_btn.configure(state='normal')
        self.api_proc=None
        self.cancel_requested=False
        self.api_status.set(f'{len(urls)} rotas compatíveis; verificando até 8 rotas. Aguarde (limite 150 segundos).')
        self.app.events.put(('line','══ API por contrato • '+host+' ══'))
        telegram=(self.app.tg_token.get(),self.app.tg_chat.get()) if self.app.tg_enabled.get() else ('','')
        command=[sys.executable,str(Path(__file__).with_name('api_probe.py')),'--base',base,'--candidates',str(out/'rotas_get.txt'),'--out',str(out),'--schemas-dir',str(out)]
        def worker():
            try:
                if all(telegram):
                    from startup_art import send_telegram_start
                    sent=send_telegram_start(*telegram,host,'API por contrato')
                    self.app.events.put(('line','[TG] Início com ASCII enviado.' if sent else '[AVISO] Telegram: falha ao enviar início com ASCII.'))
                with self.process_lock:
                    if self.cancel_requested:
                        self.jobs.put((folder,'Interrompido'))
                        return
                    self.api_proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='replace',env=env,shell=False)
                try: stdout,stderr=self.api_proc.communicate(timeout=150)
                except subprocess.TimeoutExpired:
                    self.api_proc.kill(); stdout,stderr=self.api_proc.communicate()
                for line in (stdout+'\n'+stderr).splitlines(): self.app.events.put(('line',line))
                self.jobs.put((folder,'Interrompido' if self.cancel_requested else 'Coleta encerrada; revise os status HTTP' if self.api_proc.returncode==0 else 'Falha/parcial'))
            except OSError: self.jobs.put((folder,'Falha ao executar; consulte os resultados'))
        threading.Thread(target=worker,daemon=True).start()

    def cancel_api(self):
        with self.process_lock:
            self.cancel_requested=True
            process=getattr(self,'api_proc',None)
            if process and process.poll() is None:
                process.terminate()

    def tick(self):
        try:
            folder,status=self.jobs.get_nowait()
        except queue.Empty: pass
        else:
            self.app.api_running=False; self.api_button.configure(state='normal'); self.api_status.set(status+' • '+str(folder))
            self.app.stop_btn.configure(state='disabled')
            self.folder=str(folder); self.app.output_dir=str(folder); self.app.report_btn.configure(state='normal'); self.app.out_label.set('Saída: '+str(folder)); self.refresh()
        self.tasks.delete(*self.tasks.get_children())
        groups={}
        for number,item in self.app.phase_rows.items():
            values=self.app.tree.item(item,'values')
            group='Reconhecimento' if number<=4 else 'Aplicação e APIs' if number<=10 else 'Autenticação e sessão' if number in (11,12,18,20,27,28,29) else 'Validações técnicas'
            if group not in groups: groups[group]=self.tasks.insert('','end',text=group,open=True)
            self.tasks.insert(groups[group],'end',values=values)
        self.after(1500,self.tick)
