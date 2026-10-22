#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cyberpm v1.0.0 — painel moderno, duas colunas, IP/MAC no painel."""
import os, json, queue, re, shutil, signal, subprocess, threading, time, csv, html
import sys
import shlex
from gui_helpers import log_tag, scoped_subdomains, report_links, report_path_link, execution_outcome, secret_rows
from startup_screen import WelcomeScreen
from system_clipboard import write_text
from port_review import inventory as read_port_inventory
from login_checks import check_login
from cve_guidance import guidance as cve_guidance
from audit_helpers import target_host
from cleanup_results import result_directory
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from urllib.parse import urlparse, urljoin

ROOT = Path(__file__).resolve().parent
from update_checker import display_version
APP_VERSION = display_version(ROOT)
CFG = Path.home() / '.config' / 'cyberpm'
LEGACY_CFG = Path.home() / '.config' / 'pentest-gui'
PREFS = CFG / 'preferencias.json'
TGCFG = CFG / 'telegram.json'

BG='#0d1117'; PANEL='#161b22'; PANEL2='#1c2129'; HOVER='#262c36'
BORDER='#21262d'; FG='#e6edf3'; MUTED='#8b949e'
ACCENT='#2f81f7'; GREEN='#3fb950'; RED='#f85149'; ORANGE='#d29922'
PURPLE='#a371f7'; PINK='#db61a2'; BLUE='#58a6ff'; ANON='#e3b341'

PHASES=[
 (1,'Reconhecimento'),
 (2,'Portas e serviços'),
 (3,'Tecnologias e WAF'),
 (4,'Páginas e conteúdo'),
 (5,'Análise de código'),
 (6,'JavaScript e segredos'),
 (7,'Descoberta de API'),
 (8,'Parâmetros'),
 (9,'Exposição de informações'),
 (10,'Subdomínio takeover'),
 (11,'Inventário de logins'),
 (12,'Cabeçalhos de privacidade (URL base)'),
 (13,'Métodos HTTP'),
 (14,'Cabeçalhos e TLS'),
 (15,'Vulnerabilidades'),
 (16,'CVEs identificadas'),
 (17,'SQL Injection'),
 (18,'Candidatos IDOR / BOLA'),
 (19,'XSS'),
 (20,'Revisão básica de autorização (final)'),
 (21,'OWASP ZAP (CLI)'),
 (22,'CORS mal configurado'),
 (23,'Candidatos a redirecionamento'),
 (24,'SSRF (heurística)'),
 (25,'Indícios de template (sem teste LFI)'),
 (26,'Resposta a Host alterado (sem CRLF)'),
 (27,'Coleta de identificadores'),
 (28,'Orientação para validar contas'),
 (29,'Teste de senhas (manual no Cyberpm)')]
ESSENTIAL={1,2,3,4,5,6,7,8,9,15}
PHASE_RE=re.compile(r'FASE\s+(\d+)')
ANSI=re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
SECRET=re.compile(r'(?i)(authorization:\s*(?:bearer|basic)\s+|--bearer\s+|--cookie\s+|--pass\s+|password=|token=)(\S+)')
FIND_RE=re.compile(r'\[ACHADO (CRÍTICO|ALTO|MÉDIO|BAIXO|INFORMATIVO)\]')
SEV_COLOR={'CRÍTICO':'#ff7b72','ALTO':'#ffa657','MÉDIO':'#e3b341','BAIXO':'#79c0ff','INFORMATIVO':'#8b949e'}

KNOW={
 'Arquivos sensíveis':('Acesse a URL (ex.: curl -s https://alvo/.env). Em .env veja DB_, SMTP, API keys, JWT secret. Em /.git use git-dumper.','Bloqueie /.git e .env; use variáveis de ambiente no build.'),
 'JavaScript / segredos':('Os .js estão em 29_js/arquivos. Procure AIza..., AKIA..., sk_live, ghp_ e endpoints escondidos; teste as chaves na API.','Restrinja chaves de front por domínio/permissão.'),
 'CVE potencial':('Confira os pré-requisitos e a reprodução contextual abaixo. Detecção de versão não confirma exploração.','Consulte o aviso oficial da CVE e valide a correção no componente e fluxo afetados.'),
 'XSS':('Confira o endpoint e parâmetro do log do Dalfox. Em uma conta de teste, use primeiro um marcador inofensivo e verifique onde ele é refletido no HTML/DOM. Confirme execução somente em uma prova controlada, sem acessar sessões ou dados de terceiros. Reflexão de texto sozinha não confirma XSS.','Faça codificação de saída de acordo com o contexto HTML, atributo ou JavaScript; evite inserir entrada não confiável com innerHTML e use sanitização apropriada quando HTML for necessário. CSP é uma defesa adicional e não substitui corrigir a origem da injeção.'),
 'CORS':('fetch de outro domínio com credentials.','Whitelist no Allow-Origin.'),
 'Redirecionamento aberto':('?url=https://evil.com.','Valide contra whitelist.'),
 'SSRF':('http://169.254.169.254/latest/meta-data/.','Bloqueie faixas internas.'),
 'Injeção':('SSTI {{7*7}} · LFI ../../etc/passwd.','Autoescape / normalize path.'),
 'Host header / CRLF':('%0d%0aX-Injected:%20vnc.','server_name/ALLOWED_HOSTS.'),
 'Cabeçalhos':('Sem CSP/XFO → clickjacking.','HSTS, CSP, XFO, XCTO.'),
 'Subdomínio takeover':('CNAME órfão.','Remova ou reivindique.'),
 'IDOR / BOLA':('/users/1 → /users/2.','Autorização por objeto; UUIDs.'),
 'SQLi':('Use o comando REPRODUZIR da fase SQLmap para o endpoint e parâmetro indicados, em dados de teste. Compare uma requisição normal com a requisição apontada no log; confirme a diferença reproduzível sem extrair dados reais. HTTP 403, erro genérico ou timeout não confirmam SQLi.','Use consultas parametrizadas (Prepared statements), elimine concatenação de entrada em SQL e limite as permissões da conta do banco. Valide também os pontos de ordenação e filtros que não podem ser parametrizados diretamente.'),
 'Força bruta':('Use a senha candidata no login.','Rate limit, MFA.'),
 'Métodos HTTP':('Tente PUT/DELETE.','Restrinja métodos.'),
 'API exposta':('Abra swagger/openapi e liste endpoints.','Restrinja o interno.'),
 'Recon':('Enumere subdomínios e rode 2/3/4 neles.','—'),
 'Crawl':('Use as URLs nas fases 5/7/9/29.','—'),
 'Identificadores':('Inventário de identificadores. A revisão básica de autorização roda ao final quando as fases 27/28 são selecionadas; não usa dados pessoais nem testa contas automaticamente.','Revise minimização de dados e controle de acesso com contas de teste.'),
 'Scanner — requer validação':('Reproduza manualmente.','Correção do template.'),
}
def classification(sev,cat,msg,evid=''):
    """Distingue inventário, hipótese e achado confirmado sem elevar severidade."""
    text=(cat+' '+msg+' '+evid).lower()
    if cat == 'Cabeçalhos' and re.search(r'http (?:3|4|5)\d\d', text):
        return 'INCONCLUSIVO / RESPOSTA NÃO REPRESENTATIVA', 'O cabeçalho foi avaliado em uma resposta de erro ou redirecionamento, que pode vir do proxy/WAF. Não confirma a configuração da página normal da aplicação nem uma vulnerabilidade.'
    if 'http 403' in text:
        return 'NÃO CONFIRMADO / ACESSO NEGADO', 'O servidor recusou esta requisição. A resposta não confirma o achado e não determina, sozinha, a causa do bloqueio.'
    if 'http 301' in text or 'http 302' in text:
        return 'INCONCLUSIVO / REDIRECIONAMENTO', 'Foi observado um redirecionamento; a resposta do destino precisa ser avaliada dentro do escopo.'
    if 'robots.txt' in text or 'sitemap.xml' in text:
        return 'RECURSO PÚBLICO', 'Arquivo normalmente público; não é vulnerabilidade por si só.'
    if 'parastorage.com' in text or 'thunderbolt' in text:
        return 'TECNOLOGIA / RECURSO PÚBLICO', 'Recurso de infraestrutura Wix; não comprova vulnerabilidade.'
    if cat in ('Recon','Crawl','Inventário de endpoints JS','JavaScript / segredos','Identificadores') or sev=='INFORMATIVO':
        return 'INVENTÁRIO / INFORMATIVO', 'Descoberta de recurso; não é evidência de exploração.'
    if cat in ('Possíveis segredos (não confirmados)','Scanner — requer validação','CVE potencial','IDOR / BOLA','CORS','Cabeçalhos','API exposta'):
        return 'POTENCIAL / REQUER VALIDAÇÃO', 'Verifique resposta, contexto e impacto antes de confirmar.'
    return 'ACHADO A VALIDAR', 'Necessário reproduzir e verificar o impacto.'

def finding_explanation(sev, cat, msg, evidence=''):
    status, reason = classification(sev, cat, msg, evidence)
    validate, fix = know(cat, msg)
    key = cat.split(' — ', 1)[0]
    risks = {
        'SQLi': 'Se confirmada, a manipulação de consultas pode permitir leitura ou alteração de dados conforme as permissões do banco. O log do scanner precisa demonstrar o parâmetro afetado e uma diferença reproduzível em relação à requisição de controle.',
        'XSS': 'Se confirmada, a execução de JavaScript no contexto da página pode permitir ações com os privilégios do usuário ou leitura de conteúdo acessível ao script. O impacto depende de onde o valor entra e de como é renderizado.',
        'IDOR / BOLA': 'Se confirmada com duas contas de teste, uma falha de autorização por objeto pode permitir que uma conta leia ou altere recursos de outra. Um ID numérico, isoladamente, não demonstra essa falha.',
        'CORS': 'Se uma origem não autorizada puder ler respostas sensíveis no navegador, dados podem ser expostos. Cabeçalhos isolados não comprovam leitura autenticada nem impacto.',
        'Possíveis segredos (não confirmados)': 'Se o valor for uma credencial real, válida e com privilégios, sua exposição pode permitir acesso ao serviço associado. Um nome de campo, exemplo ou chave pública não comprova esse risco.',
        'Arquivos sensíveis': 'Se o conteúdo sensível estiver acessível sem autorização, configurações, código ou credenciais podem ser expostos. HTTP 200 sozinho pode ser uma página genérica e não confirma vazamento.',
        'CVE potencial': 'O impacto depende do produto, versão, configuração e pré-requisitos descritos no aviso oficial. Uma referência à CVE não comprova que o alvo seja vulnerável.',
        'Cabeçalhos': ('Sem HSTS, o navegador pode não impor HTTPS nas visitas futuras; o risco depende do acesso por HTTP e das demais políticas do navegador. Isso não confirma interceptação nem clickjacking.' if 'hsts' in msg.lower() else 'O efeito depende do cabeçalho e do fluxo afetado. A ausência isolada não demonstra exploração; valide o comportamento real da página.'),
    }
    risk = risks.get(key, 'O impacto não foi determinado por esta evidência. É necessário identificar o comportamento afetado e reproduzi-lo antes de declarar uma vulnerabilidade.')
    if status in ('INVENTÁRIO / INFORMATIVO', 'RECURSO PÚBLICO', 'TECNOLOGIA / RECURSO PÚBLICO'):
        risk = 'Esta observação é inventário. Não foi demonstrada uma falha nem um impacto de segurança.'
        fix = 'Nenhuma correção é indicada apenas por esta observação. Compare o recurso com a política de exposição do seu projeto.'
    elif 'INCONCLUSIVO' in status or 'ACESSO NEGADO' in status:
        risk = 'Nenhum impacto foi confirmado: a coleta não representa uma resposta normal da aplicação. Primeiro obtenha uma resposta válida dentro do escopo e repita a avaliação.'
    return {'status': status, 'reason': reason, 'observation': msg,
            'impact': risk, 'validate': validate, 'fix': fix,
            'retest': 'Após corrigir, repita o mesmo teste e compare a resposta com a evidência anterior. Confirme que o comportamento esperado continua funcionando e registre o resultado.',
            'evidence': evidence}

TOOLS_BY_CATEGORY={
    'Recon':'whois, RDAP, dig, subfinder, assetfinder, curl/crt.sh',
    'Crawl':'gau, waybackurls, katana, ffuf, curl',
    'Arquivos sensíveis':'curl', 'API exposta':'curl',
    'Scanner — requer validação':'nuclei', 'SQLi':'sqlmap', 'XSS':'dalfox',
    'Cabeçalhos':'curl', 'CORS':'curl',
    'JavaScript / segredos':'curl, grep', 'Inventário de endpoints JS':'curl, grep',
    'Possíveis segredos (não confirmados)':'curl, grep',
    'CVE potencial':'nuclei/nmap, grep', 'IDOR / BOLA':'grep',
    'Identificadores':'grep'
}

def know(cat, msg=''):
    if cat == 'Cabeçalhos':
        if 'hsts' in msg.lower():
            return (
                'HSTS (Strict-Transport-Security) orienta o navegador a usar HTTPS nas próximas visitas. '
                'Sua ausência não significa SQLi, XSS, vazamento ou clickjacking. '
                'Confira uma resposta HTTPS normal (2xx) da aplicação, no mesmo host, com curl -sS -D - -o /dev/null https://SEU_DOMINIO/. '
                'Se houver 403 e server: cloudflare, o acesso foi recusado em uma resposta servida pelo proxy; não é possível atribuir essa configuração à aplicação. '
                'Repita em uma sessão de teste permitida e compare as respostas. Não interprete bloqueio como falha confirmada.',
                'Somente se a ausência for confirmada na resposta normal: configure Strict-Transport-Security no servidor/proxy que entrega HTTPS. '
                'Valide HTTPS e os certificados antes de ativar a política; includeSubDomains e preload exigem avaliar todos os subdomínios. '
                'X-Frame-Options: SAMEORIGIN é um controle separado contra enquadramento por outras origens; não substitui HSTS.')
        return (
            'Avalie cada cabeçalho na resposta normal da página. CSP frame-ancestors e X-Frame-Options controlam enquadramento; '
            'ausência isolada não confirma clickjacking. HSTS orienta uso de HTTPS; X-Content-Type-Options controla MIME sniffing. '
            'Respostas 403 do WAF não representam necessariamente a configuração da aplicação.',
            'Configure somente os controles aplicáveis e valide o comportamento em uma página acessível. '
            'SAMEORIGIN já restringe enquadramento a páginas da mesma origem; evite declarar esse controle ausente quando está presente.')
    key = cat.split(' — ',1)[0]
    return KNOW.get(key,('Compare a evidência com uma requisição de controle no mesmo endpoint e sessão de teste. Registre os pré-requisitos e o comportamento observado.', 'Corrija a causa identificada na implementação; a evidência atual não permite indicar uma alteração específica.'))
def clean(l): return ANSI.sub('', l).rstrip('\r\n')

def pick_font():
    fams=set(tkfont.families())
    for f in ('Inter','SF Pro Text','Segoe UI','Cantarell','Ubuntu','Noto Sans','DejaVu Sans','Helvetica'):
        if f in fams: return f
    return 'Helvetica'

class Cyberpm:
    def __init__(self,root):
        self.root=root; root.title('Cyberpm · v'+APP_VERSION); root.geometry(f'{min(1560,root.winfo_screenwidth()-60)}x{min(980,root.winfo_screenheight()-90)}')
        root.minsize(1000,650); root.configure(bg=BG)
        root.option_add('*Text.exportSelection', False)
        self.F=pick_font()
        self.events=queue.Queue(); self.proc=None; self.started=None; self.running=False
        self.phase_messages={n:[] for n,_ in PHASES}
        self.output_dir=None; self.phase_rows={}; self.seen_findings=0; self.find_rows={}; self.finished_phases=set(); self.current_phase=None; self.stop_requested=False; self.total_phases=29
        self.status=tk.StringVar(value='Pronto'); self.elapsed=tk.StringVar(value='00:00:00')
        self.alert_count=tk.StringVar(value='0'); self.alert_banner=tk.StringVar(value='Sem achados ainda')
        self.tool=tk.StringVar(value='—'); self.out_label=tk.StringVar(value='Saída: —')
        self.target=tk.StringVar(); self.script=tk.StringVar(value=str(ROOT/'cyberpm.sh'))
        self.scan_mode=tk.StringVar(value='Completo'); self.no_install=tk.BooleanVar(value=False)
        self.wordpress=tk.BooleanVar(value=False)
        self.tg_token=tk.StringVar(); self.tg_chat=tk.StringVar(); self.tg_enabled=tk.BooleanVar(value=True)
        self.auth_mode=tk.StringVar(value='Sem login'); self.auth_user=tk.StringVar()
        self.auth_pass=tk.StringVar(); self.auth_secret=tk.StringVar(); self.login_url=tk.StringVar()
        self.login_candidates=[]; self.session_cookie=tk.StringVar(); self.auth_status=tk.StringVar(value='Não autenticado')
        self.anon_iface=tk.StringVar(); self.use_proxychains=tk.BooleanVar(value=False)
        self.brute_url=tk.StringVar(); self.brute_user=tk.StringVar()
        self.use_wordlist=tk.BooleanVar(value=False)
        self.brute_wordlist=tk.StringVar(value=self.detect_wl()); self.brute_workers=tk.StringVar(value='5')
        self.brute_progress=tk.DoubleVar(value=0); self.brute_status=tk.StringVar(value='aguardando')
        self.brute_running=False; self.brute_stop=False
        self.login_format=tk.StringVar(value='json'); self.login_user_field=tk.StringVar(value='email')
        self.login_password_field=tk.StringVar(value='password'); self.login_marker=tk.StringVar()
        self.login_csrf=tk.StringVar(); self.login_extra=tk.StringVar(value='{}')
        self.phase_sel={n for n,_ in PHASES}; self.custom_phases=False; self.phase_codes={}
        self.load_prefs(); self.build()
        root.bind_class('Text','<Control-c>',self.copy_panel)
        root.bind_class('Text','<Control-C>',self.copy_panel)
        root.bind_class('Treeview','<Control-c>',self.copy_panel)
        root.bind_class('Treeview','<Control-C>',self.copy_panel)
        self.refresh_ports()
        if self.output_dir: self.report_btn.configure(state='normal')
        root.after(150,self.poll); root.protocol('WM_DELETE_WINDOW',self.close)

    @staticmethod
    def detect_wl():
        for c in ('/usr/share/wordlists/rockyou.txt','/usr/share/wordlists/dirb/common.txt'):
            if Path(c).exists(): return c
        return ''

    def load_prefs(self):
        try:
            path=PREFS if PREFS.exists() else LEGACY_CFG/'preferencias.json'
            d=json.loads(path.read_text()); self.use_proxychains.set(d.get('proxychains',False)); self.no_install.set(d.get('no_install',False))
        except Exception: pass
        try:
            path=TGCFG if TGCFG.exists() else LEGACY_CFG/'telegram.json'
            d=json.loads(path.read_text()); self.tg_token.set(d.get('token','')); self.tg_chat.set(d.get('chat',''))
        except Exception: pass
    def save_prefs(self):
        CFG.mkdir(parents=True,exist_ok=True); PREFS.write_text(json.dumps({'proxychains':self.use_proxychains.get(),'no_install':self.no_install.get()}))
    def save_tg(self):
        CFG.mkdir(parents=True,exist_ok=True); TGCFG.write_text(json.dumps({'token':self.tg_token.get(),'chat':self.tg_chat.get()}))

    # ───────────────────────── tema moderno ─────────────────────────
    def theme(self):
        s=ttk.Style()
        if 'clam' in s.theme_names(): s.theme_use('clam')
        F=self.F
        s.configure('.', background=BG, foreground=FG, fieldbackground=PANEL2,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, font=(F,10))
        s.configure('TFrame', background=BG); s.configure('TLabel', background=BG, foreground=FG, font=(F,10))
        s.configure('Muted.TLabel', foreground=MUTED)

        s.configure('TButton', background=PANEL2, foreground=FG, borderwidth=0,
                    focusthickness=0, padding=(12,8), font=(F,9), relief='flat')
        s.map('TButton', background=[('active',HOVER),('pressed','#2d343f')],
              foreground=[('disabled','#5b636d')])
        s.configure('Start.TButton', background=GREEN, foreground='#06210f',
                    font=(F,11,'bold'), padding=(16,11), borderwidth=0)
        s.map('Start.TButton', background=[('active','#4ac562'),('disabled','#2b3f2f')])
        s.configure('Stop.TButton', background=RED, foreground='#2a0d0c',
                    font=(F,10,'bold'), padding=(12,9), borderwidth=0)
        s.map('Stop.TButton', background=[('active','#ff6a63'),('disabled','#432827')])
        s.configure('Brute.TButton', background=PURPLE, foreground='#ffffff',
                    font=(F,10,'bold'), padding=(12,9), borderwidth=0)
        s.map('Brute.TButton', background=[('active','#b58bff'),('disabled','#33294a')])
        s.configure('Anon.TButton', background=ANON, foreground='#231a02',
                    font=(F,9,'bold'), padding=(11,7), borderwidth=0)
        s.map('Anon.TButton', background=[('active','#f0c94a')])
        s.configure('Accent.TButton', background=ACCENT, foreground='#ffffff',
                    font=(F,9,'bold'), padding=(12,8), borderwidth=0)
        s.map('Accent.TButton', background=[('active','#5a9dff')])
        # Explicit state colors prevent platform theme defaults from washing out text.
        palette={
            'TButton':('#24364b','#ffffff','#304a68','#1b2c40'),
            'Start.TButton':('#4ade80','#06210f','#75efa0','#35b965'),
            'Stop.TButton':('#ff7b72','#2a0d0c','#ffa39b','#e65f58'),
            'Accent.TButton':('#164f9f','#ffffff','#2165be','#113b78'),
            'Brute.TButton':('#c4a7ff','#211333','#dbc9ff','#aa87ed'),
            'Anon.TButton':('#f0c94a','#231a02','#ffe080','#d5aa29'),
        }
        for name,(background,foreground,active,pressed) in palette.items():
            s.configure(name,background=background,foreground=foreground,borderwidth=1,
                        bordercolor='#59718d',lightcolor=background,darkcolor=background)
            s.map(name,background=[('disabled','#283444'),('pressed',pressed),('active',active),('!disabled',background)],
                  foreground=[('disabled','#b8c6d9'),('!disabled',foreground)],
                  bordercolor=[('focus','#a5d6ff'),('!focus','#59718d')],
                  lightcolor=[('disabled','#283444'),('!disabled',background)],
                  darkcolor=[('disabled','#283444'),('!disabled',background)])
            s.configure(name,padding=(7,4),font=(F,9))

        s.configure('TEntry', fieldbackground=PANEL2, foreground=FG, insertcolor=ACCENT,
                    bordercolor=BORDER, borderwidth=1, relief='flat', padding=7)
        s.map('TEntry', bordercolor=[('focus',ACCENT)])
        s.configure('TCombobox', fieldbackground=PANEL2, background=PANEL2, foreground=FG,
                    arrowcolor=MUTED, bordercolor=BORDER, borderwidth=1, relief='flat', padding=6)
        s.map('TCombobox', fieldbackground=[('readonly',PANEL2)], bordercolor=[('focus',ACCENT)])
        self.root.option_add('*TCombobox*Listbox.background',PANEL)
        self.root.option_add('*TCombobox*Listbox.foreground',FG)
        self.root.option_add('*TCombobox*Listbox.selectBackground',ACCENT)
        s.configure('TCheckbutton', background=PANEL, foreground=FG, font=(F,9), focusthickness=0)
        s.map('TCheckbutton', background=[('active',PANEL)], foreground=[('disabled',MUTED)])

        s.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=FG,
                    borderwidth=0, relief='flat', rowheight=27, font=(F,10))
        s.configure('Treeview.Heading', background=PANEL, foreground=MUTED,
                    borderwidth=0, relief='flat', font=(F,9,'bold'), padding=6)
        s.map('Treeview', background=[('selected','#1f6feb')], foreground=[('selected','#ffffff')])
        s.map('Treeview.Heading', background=[('active',PANEL)])
        s.configure('TProgressbar', background=ACCENT, troughcolor=PANEL2, borderwidth=0, thickness=8)
        s.configure('Vertical.TScrollbar', background=PANEL2, troughcolor=BG, arrowcolor=MUTED,
                    borderwidth=0, relief='flat')
        s.configure('Horizontal.TScrollbar', background=PANEL2, troughcolor=BG, arrowcolor=MUTED, borderwidth=0)
        s.configure('TPanedwindow', background=BG)

    def card(self,parent,title,color,pady=(0,12)):
        outer=tk.Frame(parent,bg=BG); outer.pack(fill='x',pady=pady)
        box=tk.Frame(outer,bg=PANEL,highlightthickness=1,highlightbackground=BORDER)
        box.pack(fill='both',expand=True)
        head=tk.Frame(box,bg=PANEL); head.pack(fill='x',padx=15,pady=(13,7))
        tk.Frame(head,bg=color,width=4,height=15).pack(side='left',padx=(0,9))
        tk.Label(head,text=title,bg=PANEL,fg=FG,font=(self.F,10,'bold')).pack(side='left')
        descriptions={
          'ALVO':'Informe apenas domínios e aplicações dentro do escopo autorizado. Selecione o modo de auditoria.',
          'AÇÕES':'Inicia, interrompe e acompanha as fases, evidências e relatórios da auditoria.',
          'ANONIMATO · IP & MAC':'Exibe dados de rede e oferece operações locais. Alterar MAC não garante anonimato.',
          'FORÇA BRUTA':'Testes repetidos de credenciais podem bloquear contas. Não são iniciados automaticamente e exigem autorização específica.',
          'AUTENTICAÇÃO':'HTTP Basic, Bearer e Cookie usam credenciais de uma conta autorizada. Login por formulário requer integração específica.',
          'TELEGRAM':'Configura notificações e envio de relatórios. Não publique token ou relatórios sensíveis.',
          'PROGRESSO':'Mostra o andamento das fases selecionadas.',
          'FASES':'Apresenta o status de cada etapa; clique em uma fase para consultar detalhes.',
          'ACHADOS':'Indícios de segurança exigem validação manual antes de serem tratados como vulnerabilidades.',
          'LOG':'Registra mensagens e erros do processamento.',
        }
        ttk.Button(head,text='?',width=3,command=lambda t=title:messagebox.showinfo('Ajuda — '+t,descriptions.get(t,'Consulte o log e a documentação para detalhes desta seção.'))).pack(side='right')
        inner=tk.Frame(box,bg=PANEL); inner.pack(fill='both',expand=True,padx=15,pady=(0,13))
        return inner

    def scrollcol(self,parent):
        c=tk.Canvas(parent,highlightthickness=0,bg=BG)
        sb=ttk.Scrollbar(parent,orient='vertical',command=c.yview); c.configure(yscrollcommand=sb.set)
        sb.pack(side='right',fill='y'); c.pack(side='left',fill='both',expand=True)
        i=tk.Frame(c,bg=BG); w=c.create_window((0,0),window=i,anchor='nw')
        i.bind('<Configure>',lambda e:c.configure(scrollregion=c.bbox('all')))
        c.bind('<Configure>',lambda e:c.itemconfigure(w,width=e.width)); return i

    # label que usa GRID (para casar com os campos)
    def lbl(self,parent,text,row,col=0,columnspan=3,muted=False):
        tk.Label(parent,text=text,bg=PANEL,fg=(MUTED if muted else FG),font=(self.F,9)).grid(
            row=row,column=col,columnspan=columnspan,sticky='w',pady=(4,2))

    # ───────────────────────── build ─────────────────────────
    def build(self):
        self.theme()
        self.main_frame=tk.Frame(self.root,bg=BG)
        head=tk.Frame(self.main_frame,bg=BG); head.pack(fill='x',padx=18,pady=(14,8))
        dot=tk.Canvas(head,width=14,height=14,bg=BG,highlightthickness=0); dot.pack(side='left',pady=2)
        dot.create_oval(2,2,12,12,fill=ACCENT,outline='')
        tk.Label(head,text='Cyberpm',bg=BG,fg=FG,font=(self.F,17,'bold')).pack(side='left',padx=(8,0))
        tk.Label(head,text='v'+APP_VERSION,bg=BG,fg=MUTED,font=(self.F,10)).pack(side='left',padx=(8,0))
        self.status_chip=tk.Label(head,textvariable=self.status,bg=PANEL2,fg=MUTED,font=(self.F,9),padx=10,pady=3)
        self.status_chip.pack(side='left',padx=16)
        tk.Label(head,textvariable=self.alert_count,bg=BG,fg=ORANGE,font=(self.F,12,'bold')).pack(side='right',padx=(6,0))
        tk.Label(head,text='achados',bg=BG,fg=MUTED,font=(self.F,9)).pack(side='right',padx=(0,14))
        tk.Label(head,textvariable=self.elapsed,bg=BG,fg=FG,font=(self.F,11,'bold')).pack(side='right',padx=(0,14))

        actions=tk.Frame(self.main_frame,bg=BG)
        actions.pack(fill='x',padx=18,pady=(0,8))
        self.action_bar=actions
        self.start_btn=ttk.Button(actions,text='▶ Iniciar teste',style='Start.TButton',command=self.start)
        self.start_btn.pack(side='left',padx=(0,5))
        self.stop_btn=ttk.Button(actions,text='■ Parar',style='Stop.TButton',command=self.stop,state='disabled')
        self.stop_btn.pack(side='left',padx=(0,5))
        ttk.Button(actions,text='Fases…',command=self.sel_phases).pack(side='left',padx=(0,5))
        ttk.Button(actions,text='Achados',style='Accent.TButton',command=self.open_findings).pack(side='left',padx=(0,5))
        self.report_btn=ttk.Button(actions,text='Relatório',command=self.open_report,state='disabled')
        self.report_btn.pack(side='left',padx=(0,5))
        ttk.Button(actions,text='Testar login…',style='Accent.TButton',command=self.open_login_modal).pack(side='left',padx=(0,8))
        ttk.Checkbutton(actions,text='WPScan',variable=self.wordpress).pack(side='left')

        audit=ttk.Frame(self.main_frame)
        audit.pack(fill='both',expand=True,padx=14,pady=(0,14))
        pw=ttk.Panedwindow(audit,orient='horizontal'); pw.pack(fill='both',expand=True)
        self.main_panes=pw
        left=tk.Frame(pw,bg=BG); right=tk.Frame(pw,bg=BG); pw.add(left,weight=3); pw.add(right,weight=4)

        L=self.scrollcol(left)
        self.sec_alvo(L); self.sec_acoes(L); self.sec_anon(L); self.sec_brute(L); self.sec_auth(L); self.sec_tg(L)
        self.sec_right(right)
        self.welcome=WelcomeScreen(self.root,self.show_main)
        self.welcome.pack(fill='both',expand=True)

    def show_main(self):
        self.welcome.pack_forget()
        self.main_frame.pack(fill='both',expand=True)
        self.root.update_idletasks()
        self.main_panes.sashpos(0,int(self.main_panes.winfo_width()*0.43))
        self.target_entry.focus_set()

    def show_welcome(self):
        self.main_frame.pack_forget()
        self.welcome.pack(fill='both',expand=True)

    def sec_alvo(self,L):
        c=self.card(L,'ALVO',ACCENT)
        c.columnconfigure(0,weight=1)
        self.lbl(c,'Domínio',0)
        e=ttk.Entry(c,textvariable=self.target); e.grid(row=1,column=0,columnspan=3,sticky='ew'); e.focus_set()
        self.target_entry=e
        self.lbl(c,'Script',3)
        ttk.Entry(c,textvariable=self.script).grid(row=4,column=0,columnspan=2,sticky='ew')
        ttk.Button(c,text='…',width=3,command=self.browse).grid(row=4,column=2,padx=(6,0))
        r=tk.Frame(c,bg=PANEL); r.grid(row=5,column=0,columnspan=3,sticky='w',pady=(10,0))
        tk.Label(r,text='Modo',bg=PANEL,fg=MUTED,font=(self.F,9)).pack(side='left',padx=(0,8))
        ttk.Combobox(r,textvariable=self.scan_mode,state='readonly',width=12,values=('Rápido','Completo','Profundo')).pack(side='left')
        ttk.Checkbutton(c,text='Não instalar ferramentas',variable=self.no_install,command=self.save_prefs).grid(row=6,column=0,columnspan=3,sticky='w',pady=(8,0))

    def sec_acoes(self,L):
        c=self.card(L,'AÇÕES',GREEN)
        r2=tk.Frame(c,bg=PANEL); r2.pack(fill='x',pady=(8,0))
        ttk.Button(r2,text='JS & Segredos',command=self.open_secrets).pack(side='left')
        ttk.Button(r2,text='Scan PHP…',command=self.open_php2shell).pack(side='left',padx=5)
        ttk.Button(r2,text='Subdomínios',command=self.open_subdomains).pack(side='left',padx=5)
        ttk.Checkbutton(r2,text='proxychains',variable=self.use_proxychains,command=self.save_prefs).pack(side='left')
        r3=tk.Frame(c,bg=PANEL); r3.pack(fill='x',pady=(8,0))
        self.ports_btn=ttk.Button(r3,text='Portas: 0',command=self.open_ports,state='disabled')
        self.ports_btn.pack(side='left')
        ttk.Button(r3,text='Limpar resultados…',command=self.clear_results).pack(side='left',padx=5)

    def clear_results(self):
        if self.running or self.brute_running:
            return messagebox.showinfo('Limpar resultados','Aguarde a execução terminar antes de apagar os resultados.')
        if not self.output_dir:
            return messagebox.showinfo('Limpar resultados','Nenhuma auditoria selecionada.')
        try:
            directory=result_directory(ROOT/'cyberpm-out',self.output_dir)
        except ValueError as exc:
            return messagebox.showwarning('Limpar resultados',str(exc))
        if not messagebox.askyesno('Apagar auditoria local',f'Apagar permanentemente a pasta abaixo, incluindo relatórios e arquivos baixados?\n\n{directory}'):
            return
        try:
            shutil.rmtree(directory)
        except OSError as exc:
            return messagebox.showerror('Limpar resultados',f'Não foi possível concluir a exclusão: {exc}')
        self.output_dir=None; self.finished_phases.clear(); self.current_phase=None; self.phase_messages={n:[] for n,_ in PHASES}
        self.seen_findings=0; self.find_rows={}; self.started=None
        self.out_label.set('Saída: —'); self.alert_count.set('0'); self.alert_banner.set('Sem achados ainda')
        self.log.delete('1.0','end'); self.status.set('Pronto'); self.status_chip.configure(fg=MUTED)
        self.progress['value']=0; self.progress_text.set('Resultados locais removidos'); self.elapsed.set('00:00:00')
        self.report_btn.configure(state='disabled'); self.refresh_ports(); self.save_prefs()
        for n in self.phase_rows: self.tree.set(self.phase_rows[n],'s','Pendente')
        if hasattr(self,'ftree') and self.ftree.winfo_exists(): self.ftree.delete(*self.ftree.get_children())
        if hasattr(self,'stree') and self.stree.winfo_exists(): self.stree.delete(*self.stree.get_children())

    def refresh_ports(self):
        path=Path(self.output_dir)/'02_portas'/'portas.json' if self.output_dir else None
        try:
            host,ports=read_port_inventory(path)
            saved=time.strftime('%d/%m/%Y %H:%M',time.localtime(path.stat().st_mtime))
        except (OSError,ValueError,KeyError,TypeError):
            host=''; ports=[]; saved=''
        short_host=host if len(host)<=18 else host[:15]+'…'
        label=f'Portas: {len(ports)} · {short_host}' if host else 'Portas: 0'
        self.ports_btn.configure(text=label,state='normal' if ports else 'disabled')

    def open_ports(self):
        if not self.output_dir: return
        path=Path(self.output_dir)/'02_portas'/'portas.json'
        try:
            host,ports=read_port_inventory(path)
        except (OSError,ValueError,KeyError,TypeError) as exc:
            return messagebox.showwarning('Portas',f'Inventário indisponível: {exc}')
        window=tk.Toplevel(self.root); window.title('Portas descobertas — '+host); window.geometry('700x440'); window.configure(bg=BG)
        tk.Label(window,text='Serviços do alvo salvo: '+host,bg=BG,fg=FG).pack(anchor='w',padx=12,pady=12)
        saved=time.strftime('%d/%m/%Y %H:%M',time.localtime(path.stat().st_mtime))
        tk.Label(window,text=f'Resultado salvo · arquivo de {saved}\nFonte: {path}\nAbrir esta janela não executa uma nova varredura.',bg=BG,fg=MUTED,wraplength=660,justify='left').pack(anchor='w',padx=12)
        text=tk.Text(window,bg=PANEL,fg=FG,height=12,wrap='word'); text.pack(fill='both',expand=True,padx=12)
        try: content=(path.parent/'portas.txt').read_text(errors='replace')
        except OSError: content='\n'.join(f'{port}/tcp — inventário salvo' for port in ports)
        text.insert('end',content); text.configure(state='disabled')
        selected=tk.StringVar(value=','.join(map(str,ports)))
        tk.Label(window,text='Portas para revisar (separadas por vírgula)',bg=BG,fg=MUTED).pack(anchor='w',padx=12,pady=(10,2))
        ttk.Entry(window,textvariable=selected).pack(fill='x',padx=12)
        def execute():
            if self.running: return messagebox.showinfo('Portas','Aguarde a execução atual terminar.')
            if self.brute_running: return messagebox.showinfo('Portas','Aguarde os testes de login terminarem.')
            try:
                values={int(item.strip()) for item in selected.get().split(',') if item.strip()}
                if not values or not values.issubset(ports): raise ValueError()
            except ValueError:
                return messagebox.showwarning('Portas','Selecione somente portas do inventário, separadas por vírgula.')
            args=[sys.executable,'-u',str(ROOT/'port_review.py'),'--inventory',str(path),'--ports',','.join(map(str,sorted(values)))]
            if self.no_install.get(): args.append('--no-install')
            try:
                proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,cwd=str(ROOT),start_new_session=True)
            except OSError as exc:
                return messagebox.showerror('Portas',str(exc))
            self.proc=proc; self.running=True; self.stop_requested=False; self.current_phase=None; self.started=time.time()
            self.start_btn.configure(state='disabled'); self.stop_btn.configure(state='normal'); self.report_btn.configure(state='disabled')
            self.status.set('Revisando portas'); self.status_chip.configure(fg=ACCENT)
            window.destroy(); threading.Thread(target=self.reader,daemon=True).start(); self.root.after(1000,self.tick)
        ttk.Button(window,text='Testar serviços das portas selecionadas',command=execute,state='disabled' if self.running else 'normal').pack(pady=12)

    def sec_anon(self,L):
        c=self.card(L,'ANONIMATO · IP & MAC',ANON)
        tk.Label(c,text='Opcional — troque identidade antes de varrer.',bg=PANEL,fg=MUTED,font=(self.F,9)).pack(anchor='w')
        r=tk.Frame(c,bg=PANEL); r.pack(fill='x',pady=(8,6))
        tk.Label(r,text='Interface',bg=PANEL,fg=MUTED,font=(self.F,9)).pack(side='left',padx=(0,8))
        ttk.Entry(r,textvariable=self.anon_iface,width=10).pack(side='left')
        ttk.Button(r,text='Detectar',style='Anon.TButton',command=self.anon_detect).pack(side='left',padx=6)
        ttk.Button(r,text='Ver IP/MAC',command=self.anon_check).pack(side='left')
        g=tk.Frame(c,bg=PANEL); g.pack(fill='x',pady=2)
        ttk.Button(g,text='🔄  Trocar MAC',style='Anon.TButton',command=self.anon_mac).pack(side='left')
        ttk.Button(g,text='♻  Renovar IP',style='Anon.TButton',command=self.anon_ip).pack(side='left',padx=6)
        ttk.Button(g,text='↺  MAC original',command=self.anon_mac_restore).pack(side='left')
        g2=tk.Frame(c,bg=PANEL); g2.pack(fill='x',pady=(6,0))
        ttk.Button(g2,text='🧅 Tor ON',style='Anon.TButton',command=lambda:self.anon_run(['bash','-lc','systemctl start tor'],'tor',True)).pack(side='left')
        ttk.Button(g2,text='Tor OFF',command=lambda:self.anon_run(['bash','-lc','systemctl stop tor'],'tor',True)).pack(side='left',padx=6)
        ttk.Button(g2,text='AnonSurf ON',style='Anon.TButton',command=lambda:self.anon_run(['bash','-lc','anonsurf start'],'anonsurf',True)).pack(side='left')
        ttk.Button(g2,text='OFF',command=lambda:self.anon_run(['bash','-lc','anonsurf stop'],'anonsurf',True)).pack(side='left',padx=6)

    def sec_brute(self,L):
        c=self.card(L,'TESTE DE SENHAS · UMA CONTA',PINK)
        c.columnconfigure(0,weight=1); c.columnconfigure(1,weight=1)
        self.lbl(c,'1. URL que recebe o login (requisição POST)',0)
        ttk.Entry(c,textvariable=self.brute_url).grid(row=1,column=0,columnspan=2,sticky='ew')
        ttk.Button(c,text='🔎',width=3,command=self.detect_api).grid(row=1,column=2,padx=(6,0))
        self.lbl(c,'2. Usuário ou e-mail da conta de teste',2)
        ttk.Entry(c,textvariable=self.brute_user).grid(row=3,column=0,columnspan=3,sticky='ew')
        self.lbl(c,'3. Senhas candidatas (uma por linha)',4)
        self.brute_pw=tk.Text(c,height=4,bg=PANEL2,fg=FG,insertbackground=ACCENT,font=('Monospace',10),
                              relief='flat',highlightthickness=1,highlightbackground=BORDER,highlightcolor=ACCENT)
        self.brute_pw.grid(row=5,column=0,columnspan=3,sticky='ew')
        r=tk.Frame(c,bg=PANEL); r.grid(row=6,column=0,columnspan=3,sticky='w',pady=(6,0))
        ttk.Button(r,text='Importar',command=self.import_pw).pack(side='left')
        ttk.Button(r,text='Limpar',command=lambda:(self.brute_pw.delete('1.0','end'))).pack(side='left',padx=6)
        tk.Label(r,text='Uma conta · intervalo 1s · até 50 senhas',bg=PANEL,fg=MUTED,font=(self.F,9)).pack(side='left',padx=(12,6))
        r2=tk.Frame(c,bg=PANEL); r2.grid(row=7,column=0,columnspan=3,sticky='ew',pady=(8,0)); r2.columnconfigure(1,weight=1)
        ttk.Checkbutton(r2,text='Usar wordlist',variable=self.use_wordlist,command=self.toggle_wordlist).grid(row=0,column=0,columnspan=3,sticky='w',pady=(0,6))
        self.wordlist_entry=ttk.Entry(r2,textvariable=self.brute_wordlist,state='disabled')
        self.wordlist_entry.grid(row=1,column=0,columnspan=2,sticky='ew')
        self.wordlist_button=ttk.Button(r2,text='…',width=3,command=self.browse_wl,state='disabled')
        self.wordlist_button.grid(row=1,column=2,padx=(6,0))
        rb=tk.Frame(c,bg=PANEL); rb.grid(row=8,column=0,columnspan=3,sticky='ew',pady=(10,4))
        ttk.Button(rb,text='Como usar',command=self.login_help).pack(side='right')
        self.brute_btn=ttk.Button(rb,text='▶  TESTAR SENHAS',style='Brute.TButton',command=self.brute_force); self.brute_btn.pack(side='left')
        ttk.Button(rb,text='■',width=3,command=self.stop_brute).pack(side='left',padx=6)
        ttk.Progressbar(c,variable=self.brute_progress,maximum=100).grid(row=9,column=0,columnspan=3,sticky='ew')
        tk.Label(c,textvariable=self.brute_status,bg=PANEL,fg=MUTED,font=(self.F,9)).grid(row=10,column=0,columnspan=3,sticky='w',pady=(4,0))
        settings=tk.Frame(c,bg=PANEL); settings.grid(row=11,column=0,columnspan=3,sticky='ew',pady=8)
        for row,label,var in ((0,'Campo usuário',self.login_user_field),(1,'Campo senha',self.login_password_field),
                              (3,'Marcador de sucesso',self.login_marker),(4,'Campo CSRF (opcional)',self.login_csrf),(5,'Campos extras (JSON)',self.login_extra)):
            tk.Label(settings,text=label,bg=PANEL,fg=MUTED).grid(row=row,column=0,sticky='w',pady=2)
            ttk.Entry(settings,textvariable=var).grid(row=row,column=1,sticky='ew',padx=6)
        settings.columnconfigure(1,weight=1)
        tk.Label(settings,text='Formato',bg=PANEL,fg=MUTED).grid(row=2,column=0,sticky='w')
        ttk.Combobox(settings,textvariable=self.login_format,values=('json','form'),state='readonly',width=12).grid(row=2,column=1,sticky='w',padx=6)
        tk.Label(c,text='Configure os campos acima antes de iniciar. HTTP 200/302 sozinho não confirma login.\nParada em sucesso indicado, bloqueio ou erro. CAPTCHA/MFA exigem login manual.',bg=PANEL,fg=MUTED,justify='left',wraplength=360).grid(row=12,column=0,columnspan=3,sticky='w')

    def login_help(self):
        messagebox.showinfo('Teste de senhas — como usar',
            '1. Informe o Alvo e a URL real do POST de login (veja Rede/Network no navegador).\n'
            '2. Informe uma conta de teste e até 50 senhas, uma por linha. Wordlist é um arquivo de senhas candidatas.\n'
            '3. Copie do POST os nomes dos campos: por exemplo email/password. Selecione json ou form conforme a requisição.\n'
            '4. Para HTML, informe um texto exclusivo da área autenticada no Marcador de sucesso. CSRF e Campos extras são opcionais, conforme o formulário.\n'
            '5. Clique em Testar senhas. O log e 20_brute/login_resultados.json mostram o resultado por tentativa, sem salvar senhas.\n\n'
            'Há intervalo de 1 segundo e parada em bloqueio, erro ou sucesso indicado. Pode bloquear a conta. CAPTCHA e MFA precisam de login manual. A fase 29 da varredura não inicia este teste automaticamente.')

    def sec_auth(self,L):
        c=self.card(L,'ACESSO ÀS PÁGINAS PROTEGIDAS',PURPLE)
        tk.Label(c,text='Opcional: usa uma sessão autorizada DURANTE a varredura.\nNão testa senhas nem descobre contas.',bg=PANEL,fg=MUTED,justify='left',wraplength=360).pack(anchor='w',pady=(0,7))
        r=tk.Frame(c,bg=PANEL); r.pack(fill='x')
        tk.Label(r,text='Método de acesso',bg=PANEL,fg=FG).pack(anchor='w')
        combo=ttk.Combobox(r,textvariable=self.auth_mode,state='readonly',values=('Sem login','HTTP Basic','Bearer','Cookie','Sessão do navegador'))
        combo.pack(fill='x',pady=(3,7))
        self.auth_fields=tk.Frame(c,bg=PANEL); self.auth_fields.pack(fill='x')
        def refresh(*_):
            for w in self.auth_fields.winfo_children(): w.destroy()
            mode=self.auth_mode.get()
            def field(label,var,secret=False):
                tk.Label(self.auth_fields,text=label,bg=PANEL,fg=MUTED).pack(anchor='w',pady=(4,2))
                ttk.Entry(self.auth_fields,textvariable=var,show='•' if secret else '').pack(fill='x')
            if mode=='HTTP Basic':
                field('Usuário da conta autorizada',self.auth_user)
                field('Senha',self.auth_pass,True)
            elif mode in ('Bearer','Cookie'):
                field('Token Bearer' if mode=='Bearer' else 'Cookie de sessão',self.auth_secret,True)
            elif mode=='Sessão do navegador':
                ttk.Button(self.auth_fields,text='Abrir navegador para entrar',command=self.browser_login).pack(anchor='w',pady=5)
                tk.Label(self.auth_fields,textvariable=self.auth_status,bg=PANEL,fg=MUTED,wraplength=350).pack(anchor='w')
            else:
                tk.Label(self.auth_fields,text='A varredura será feita sem autenticação.',bg=PANEL,fg=MUTED).pack(anchor='w')
        combo.bind('<<ComboboxSelected>>',refresh)
        refresh()

    def open_login_modal(self):
        """Single-account login helper; no credential guessing or arbitrary form submission."""
        target=self.target.get().strip()
        host=urlparse(target if '://' in target else 'https://'+target).hostname
        if not host:
            return messagebox.showwarning('Alvo','Informe o domínio antes de testar o login.')
        win=tk.Toplevel(self.root); win.title('Cyberpm — Testar login autorizado')
        win.geometry('510x350'); win.configure(bg=BG); win.transient(self.root); win.grab_set()
        frame=tk.Frame(win,bg=BG); frame.pack(fill='both',expand=True,padx=20,pady=15)
        tk.Label(frame,text='TESTAR LOGIN',font=(self.F,14,'bold'),bg=BG,fg=FG).pack(anchor='w')
        tk.Label(frame,text='Uma conta de teste, somente no host informado.\nPara formulários web, entre manualmente no navegador.',justify='left',bg=BG,fg=MUTED).pack(anchor='w',pady=(4,12))
        tk.Label(frame,text='URL da página de login',bg=BG,fg=FG).pack(anchor='w')
        if not self.login_url.get(): self.login_url.set(target if '://' in target else 'https://'+target)
        ttk.Entry(frame,textvariable=self.login_url).pack(fill='x',pady=(3,9))
        tk.Label(frame,text='Identificador da conta de teste (CPF, e-mail ou usuário)',bg=BG,fg=FG).pack(anchor='w')
        ttk.Entry(frame,textvariable=self.auth_user).pack(fill='x',pady=(3,9))
        tk.Label(frame,text='Senha (não é salva)',bg=BG,fg=FG).pack(anchor='w')
        ttk.Entry(frame,textvariable=self.auth_pass,show='•').pack(fill='x',pady=(3,9))
        def open_browser():
            url=self.login_url.get().strip(); parsed=urlparse(url)
            if parsed.scheme not in ('http','https') or parsed.hostname!=host:
                return messagebox.showerror('Escopo','A URL deve ser HTTP(S) e pertencer ao host do alvo.',parent=win)
            win.grab_release(); win.destroy()
            self.browser_login()
        ttk.Button(frame,text='Abrir login no navegador',style='Accent.TButton',command=open_browser).pack(anchor='w',pady=(8,3))
        tk.Label(frame,text='O login de formulário não é enviado automaticamente.\nA sessão capturada precisa ser validada no próprio site.',bg=BG,fg=MUTED,justify='left').pack(anchor='w',pady=(7,0))

    def discover_logins(self):
        """Read prior crawl results without sending credentials to discovered pages."""
        target=self.target.get().strip()
        host=urlparse(target if '://' in target else 'https://'+target).hostname
        if not host:
            return messagebox.showwarning('Login','Informe o domínio do alvo primeiro.')
        paths=[ROOT/'cyberpm-out'/host/'17_logins'/'logins.txt',ROOT/'cyberpm-out'/host/'04_crawl'/'urls.txt']
        candidates=[]
        for path in paths:
            if not path.exists(): continue
            for line in path.read_text(errors='replace').splitlines():
                url=line.strip().split()[0] if line.strip() else ''
                parsed=urlparse(url)
                if parsed.hostname==host and re.search(r'login|signin|entrar|autentica|acesso',parsed.path,re.I) and url not in candidates:
                    candidates.append(url)
        self.login_candidates=candidates[:100]
        if not candidates:
            return messagebox.showinfo('Login','Nenhuma URL de login identificada no inventário local. Informe a URL manualmente.')
        dlg=tk.Toplevel(self.root); dlg.title('Logins encontrados no escopo'); dlg.geometry('760x360')
        tk.Label(dlg,text='Selecione uma página de login do domínio autorizado:').pack(anchor='w',padx=10,pady=8)
        lb=tk.Listbox(dlg); lb.pack(fill='both',expand=True,padx=10)
        for url in self.login_candidates: lb.insert('end',url)
        def choose():
            if lb.curselection(): self.login_url.set(self.login_candidates[lb.curselection()[0]]); dlg.destroy()
        ttk.Button(dlg,text='Usar URL selecionada',command=choose).pack(pady=8)

    def browser_login(self):
        """Interactive user login, never auto-submit credentials to crawled URLs."""
        target=self.target.get().strip()
        host=urlparse(target if '://' in target else 'https://'+target).hostname
        login=self.login_url.get().strip() or (target if '://' in target else 'https://'+target)
        parsed=urlparse(login)
        if not host or parsed.scheme not in ('https','http') or parsed.hostname!=host:
            return messagebox.showerror('Escopo','A URL de login precisa pertencer ao host do alvo autorizado.')
        if not messagebox.askyesno('Sessão autenticada','Abrir navegador para autenticação manual com CPF/e-mail e senha? A sessão será usada apenas no host informado. Não execute auditorias em sistemas sem autorização.'):
            return
        self.auth_status.set('Navegador abrindo...')
        threading.Thread(target=self._browser_login_worker,args=(login,host),daemon=True).start()

    def _browser_login_worker(self,login,host):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.root.after(0,lambda:messagebox.showerror('Dependência','Instale Playwright: python3 -m pip install playwright; python3 -m playwright install chromium (em ambiente virtual).'))
            self.root.after(0,lambda:self.auth_status.set('Playwright não instalado'))
            return
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=False)
                ctx=browser.new_context()
                page=ctx.new_page(); page.goto(login,wait_until='domcontentloaded',timeout=30000)
                done=threading.Event()
                self.root.after(0,lambda:self._confirm_browser_login(done))
                if not done.wait(timeout=300):
                    browser.close(); self.root.after(0,lambda:self.auth_status.set('Login cancelado/expirado')); return
                cookies=[c for c in ctx.cookies() if c.get('domain','').lstrip('.')==host]
                cookie='; '.join(c['name']+'='+c['value'] for c in cookies)
                browser.close()
            self.root.after(0,lambda:self._set_browser_cookie(cookie))
        except Exception as exc:
            msg=str(exc)[:250]
            self.root.after(0,lambda:messagebox.showerror('Navegador',msg))
            self.root.after(0,lambda:self.auth_status.set('Erro na autenticação'))

    def _confirm_browser_login(self,done):
        messagebox.showinfo('Login manual','Faça login no navegador com sua conta de teste. Quando concluir, volte aqui e clique OK. Não feche o navegador antes.')
        done.set()

    def _set_browser_cookie(self,cookie):
        if not cookie:
            self.auth_status.set('Nenhum cookie encontrado; sessão não validada')
            return messagebox.showwarning('Sessão','Nenhum cookie de sessão do host foi encontrado. Verifique o login.')
        self.session_cookie.set(cookie); self.auth_mode.set('Sessão do navegador')
        self.auth_status.set('Cookies capturados; confirme acesso autenticado antes da auditoria')

    def sec_tg(self,L):
        c=self.card(L,'TELEGRAM',BLUE)
        c.columnconfigure(0,weight=1); c.columnconfigure(1,weight=1)
        ttk.Checkbutton(c,text='Enviar notificações',variable=self.tg_enabled).grid(row=0,column=0,columnspan=3,sticky='w')
        self.lbl(c,'Token',1); ttk.Entry(c,textvariable=self.tg_token,show='•').grid(row=2,column=0,columnspan=3,sticky='ew')
        self.lbl(c,'Chat ID',3); ttk.Entry(c,textvariable=self.tg_chat).grid(row=4,column=0,columnspan=3,sticky='ew')
        r=tk.Frame(c,bg=PANEL); r.grid(row=5,column=0,columnspan=3,sticky='w',pady=(8,0))
        ttk.Button(r,text='Salvar',command=self.save_tg).pack(side='left',padx=(0,6)); ttk.Button(r,text='Testar',command=self.test_tg).pack(side='left')

    def sec_right(self,R):
        c=self.card(R,'PROGRESSO',ORANGE,pady=(0,10))
        self.progress=ttk.Progressbar(c,maximum=len(PHASES)); self.progress.pack(fill='x')
        self.progress_text=tk.StringVar(value=f'0 de {len(PHASES)} fases')
        tk.Label(c,textvariable=self.progress_text,bg=PANEL,fg=MUTED,font=(self.F,9)).pack(anchor='w',pady=(5,0))
        tk.Label(c,textvariable=self.out_label,bg=PANEL,fg=MUTED,font=(self.F,9),wraplength=600).pack(anchor='w')
        panels=ttk.Panedwindow(R,orient='vertical'); panels.pack(fill='both',expand=True)
        phases=tk.Frame(panels,bg=BG); logs=tk.Frame(panels,bg=BG)
        panels.add(phases,weight=2); panels.add(logs,weight=5)
        c=self.card(phases,'FASES',ACCENT,pady=(0,5))
        c.master.master.pack_configure(fill='both',expand=True)
        self.tree=ttk.Treeview(c,columns=('n','s','a'),show='headings',height=7)
        self.tree.heading('n',text='Fase'); self.tree.heading('s',text='Situação')
        self.tree.column('n',width=320); self.tree.column('s',width=130)
        self.tree.heading('a',text='Ação'); self.tree.column('a',width=70,stretch=False,anchor='center')
        self.tree.pack(side='left',fill='both',expand=True); self.tree.bind('<Double-1>',self.open_phase_detail)
        sb=ttk.Scrollbar(c,orient='vertical',command=self.tree.yview); sb.pack(side='right',fill='y'); self.tree.configure(yscrollcommand=sb.set)
        for n,nm in PHASES: self.phase_rows[n]=self.tree.insert('','end',values=(f'{n:02d}   {nm}','Pendente','Pular'))
        self.tree.bind('<ButtonRelease-1>',self.phase_action)
        self.tree.bind('<Motion>',self.phase_hover)
        self.tree.bind('<Leave>',self.hide_phase_tip)
        self.tree.bind('<ButtonPress>',self.hide_phase_tip,add='+')
        self.tree.bind('<MouseWheel>',self.hide_phase_tip,add='+')
        self.tree.bind('<Button-4>',self.hide_phase_tip,add='+')
        self.tree.bind('<Button-5>',self.hide_phase_tip,add='+')
        c=self.card(logs,'LOG',MUTED,pady=(0,0))
        c.master.master.pack_configure(fill='both',expand=True)
        actions=tk.Frame(c,bg=PANEL); actions.pack(fill='x',pady=(0,6))
        ttk.Button(actions,text='Limpar log',command=self.clear_log).pack(side='right',padx=(6,0))
        ttk.Button(actions,text='Copiar log',command=lambda:self.copy_panel(widget=self.log)).pack(side='right')
        body=tk.Frame(c,bg=PANEL); body.pack(fill='both',expand=True)
        body.rowconfigure(0,weight=1); body.columnconfigure(0,weight=1)
        self.log=tk.Text(body,wrap='none',bg='#0b0e13',fg='#c9d1d9',insertbackground=ACCENT,font=('Monospace',10),
                         relief='flat',highlightthickness=1,highlightbackground=BORDER)
        for tag,color in {'normal':FG,'info':BLUE,'phase':PURPLE,'success':GREEN,'warning':ORANGE,'error':RED,'critical':'#ff7b72','finding':PINK}.items():
            self.log.tag_configure(tag,foreground=color)
        self.log.grid(row=0,column=0,sticky='nsew')
        sb=ttk.Scrollbar(body,orient='vertical',command=self.log.yview)
        sb.grid(row=0,column=1,sticky='ns'); self.log.configure(yscrollcommand=sb.set)
        horizontal=ttk.Scrollbar(body,orient='horizontal',command=self.log.xview)
        horizontal.grid(row=1,column=0,sticky='ew'); self.log.configure(xscrollcommand=horizontal.set)
        self.log_panes=panels
        self.log_split_initialized=False
        panels.bind('<Configure>',self.initialize_log_split)

    def initialize_log_split(self,event=None):
        if self.log_split_initialized: return
        height=self.log_panes.winfo_height()
        if height<200: return
        self.log_panes.sashpos(0,max(100,int(height*0.3)))
        self.log_split_initialized=True

    def clear_log(self):
        self.log.delete('1.0','end')

    def copy_panel(self,event=None,widget=None):
        widget=widget if widget is not None else event.widget
        if isinstance(widget,tk.Text):
            # Keep the text selection independent of clipboard ownership on X11.
            widget.configure(exportselection=False)
            text=widget.get('sel.first','sel.last') if widget.tag_ranges('sel') else widget.get('1.0','end-1c')
        elif isinstance(widget,ttk.Treeview):
            text='\n'.join('\t'.join(str(value) for value in (widget.item(item,'text'),*widget.item(item,'values'))) for item in widget.selection())
        else: return
        if text:
            write_text(self.root,text)
        return 'break'

    def hide_phase_tip(self,event=None):
        tip=getattr(self,'phase_tip',None)
        if tip is not None and tip.winfo_exists(): tip.destroy()
        self.phase_tip=None; self.phase_tip_row=None

    def phase_hover(self,event):
        row=self.tree.identify_row(event.y)
        if row==getattr(self,'phase_tip_row',None): return
        self.hide_phase_tip()
        phase=next((n for n,item in self.phase_rows.items() if item==row),None)
        if phase is None: return
        self.phase_tip_row=row
        tip=tk.Toplevel(self.root); self.phase_tip=tip
        tip.overrideredirect(True)
        tk.Label(tip,text=f'Fase {phase:02d} · Ferramentas previstas\n{self.PHASE_TOOLS.get(phase,"Consultar log")}',
                 bg=PANEL2,fg=FG,justify='left',padx=10,pady=7,wraplength=360,
                 relief='solid',borderwidth=1).pack()
        tip.update_idletasks()
        x=max(0,min(event.x_root+14,tip.winfo_screenwidth()-tip.winfo_reqwidth()))
        y=max(0,min(event.y_root+18,tip.winfo_screenheight()-tip.winfo_reqheight()))
        tip.geometry(f'+{x}+{y}')

    # Inventário de cada fase, independente de ser vulnerabilidade.
    PHASE_FILES={
        1:('01_recon',['dominio_resumo.txt','dominio_dados.json','dns_avancado.json','rdap.json','dns.txt','whois.txt','subs.txt','ferramentas.tsv']),
        2:('02_portas',['portas.txt','nmap.txt','resumo.txt','scan_status.json','nmap.exec.txt','nmap.stderr','nmap.stdout','tcp_status.tsv','port_review.txt','port_summary.txt','port_review_status.json','port_review.stderr','database_review.json']),
        3:('03_tech',['whatweb.txt','waf.txt','tech.txt','wpscan.stdout','wpscan.stderr']),
        4:('04_crawl',['urls.txt']),
        5:('08_codigo',['coleta_status.txt','curl.stderr','js.txt','comentarios.txt','indicadores.txt']),
        6:('29_js',['endpoints.tsv','segredos.tsv','download_erros.tsv','lista.txt','retire.json','retire.stderr']),
        7:('06_api',['operacoes.tsv','apis.txt','candidatos.txt','api_resultados.tsv','api_resultados.json','api_probe.stderr']), 8:('07_params',['params.txt','com_param.txt','arjun.stdout','arjun.stderr']),
        9:('05_exposicao',['env_keys.txt','status.tsv']),10:('21_takeover',['cnames.txt']),
        11:('17_logins',['logins.txt']),12:('16_privacidade',['headers.txt','curl.stderr']),
        13:('24_metodos',['metodos.txt','curl.stderr']),14:('26_headers',['headers.txt','testssl.json','testssl.stdout','testssl.stderr']),
        15:('09_vulns',['alvos.txt','nuclei.txt','nuclei.exec.txt','nuclei.stderr']),16:('10_cves',['resumo.txt','status.json','ids.txt','cves.txt','cve.exec.txt','cve.stderr']),
        17:('11_sqli',['cobertura.tsv','candidatos.txt','selecionados.txt','sqlmap.log','interrupcao.txt']),18:('12_idor',['ids.txt']),19:('13_xss',['cobertura.tsv','xss_candidatos.txt','dalfox.log']),
        20:('14_authz',['admin.txt']),21:('15_zap',['zap.txt']),
        22:('22_cors',['cors.txt']),23:('23_redirect',['candidatos.txt']),
        24:('25_ssrf',['candidatos.txt']),25:('27_injecao',['ssti.txt','curl.stderr']),
        26:('28_hosthdr',['hosthdr.txt','curl.stderr']),27:('18_ident',['dados_sensiveis_mascarados.tsv']),
        28:('19_validacao',['validados.txt']),29:('20_brute',['login_resultados.json']),
    }
    PHASE_TOOLS={1:'whois, RDAP, dig, subfinder, assetfinder, crt.sh',2:'nmap',3:'whatweb, wafw00f, curl',
                 4:'gau, waybackurls, katana, ffuf, curl',5:'curl, grep',6:'js_downloader.py, Retire.js, grep',
                 7:'curl, api_probe.py (GET/OPTIONS)',8:'grep, Arjun',9:'curl',10:'dig',11:'grep',12:'curl',13:'curl',14:'curl, testssl.sh',
                 15:'nuclei',16:'grep',17:'sqlmap',18:'grep',19:'dalfox',20:'curl',21:'OWASP ZAP',
                 22:'curl',23:'grep',24:'grep',25:'grep',26:'curl',27:'grep',28:'grep',29:'Cyberpm / manual'}

    def phase_data(self,n,limit=150):
        folder,names=self.PHASE_FILES.get(n,('',[]))
        base=Path(self.output_dir or ROOT/'cyberpm-out')/folder
        output=[]
        for name in names:
            path=base/name
            if not path.is_file(): continue
            try:
                lines=path.read_text(encoding='utf-8',errors='replace').splitlines()
                output.append((name,len(lines),'\n'.join(lines if limit is None else lines[:limit])))
            except OSError: pass
        return output

    def open_phase_detail(self,_event=None):
        if _event is not None and self.tree.identify_column(_event.x)=='#3':
            return 'break'
        selected=self.tree.selection()
        if not selected: return
        vals=self.tree.item(selected[0],'values')
        if not vals: return
        try: n=int(str(vals[0]).split()[0])
        except (ValueError,IndexError): return
        name=dict(PHASES).get(n,'Fase')
        w=tk.Toplevel(self.root); w.title(f'Fase {n:02d} — {name}'); w.geometry('1000x700'); w.configure(bg=BG)
        tk.Label(w,text=f'FASE {n:02d} — {name}  |  Ferramentas: {self.PHASE_TOOLS.get(n,"Consultar logs")}',
                 bg=PANEL,fg=FG,font=(self.F,11,'bold'),padx=12,pady=12,anchor='w').pack(fill='x')
        txt=tk.Text(w,bg='#0b0e13',fg=FG,font=('Monospace',10),wrap='none')
        scroll=ttk.Scrollbar(w,orient='vertical',command=txt.yview); txt.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y'); txt.pack(fill='both',expand=True,padx=10,pady=10)
        def refresh():
            txt.configure(state='normal'); txt.delete('1.0','end')
            messages=getattr(self,'phase_messages',{}).get(n,[])
            txt.insert('end','══ LOG DA FASE ══\n'+'\n'.join(messages)+'\n\n')
            data=self.phase_data(n)
            if not data: txt.insert('end','Ainda não existem arquivos de inventário desta fase.\n')
            for filename,count,content in data:
                txt.insert('end',f'\n══ {filename} ({count} linhas) ══\n{content}\n')
            txt.configure(state='disabled')
        ttk.Button(w,text='↻ Atualizar detalhes',command=refresh).pack(pady=(0,10))
        refresh()

    # ───────────────────── ações básicas ─────────────────────
    def browse(self):
        p=filedialog.askopenfilename(initialdir=str(ROOT),filetypes=[('Shell','*.sh'),('Todos','*')])
        if p: self.script.set(p)

    def open_subdomains(self):
        if not self.output_dir:
            return messagebox.showinfo('Subdomínios','Execute a fase 1 para descobrir subdomínios.')
        folder=Path(self.output_dir)
        source=folder/'01_recon'/'subs.txt'
        try:
            hosts=scoped_subdomains(source.read_text(encoding='utf-8',errors='replace').splitlines(),folder.name)
        except OSError as exc:
            return messagebox.showwarning('Subdomínios',f'Inventário indisponível: {exc}')
        w=tk.Toplevel(self.root); w.title('Subdomínios descobertos'); w.geometry('740x480'); w.configure(bg=BG)
        ttk.Label(w,text='Selecione um subdomínio autorizado para executar as fases e o modo atuais.',wraplength=700).pack(padx=12,pady=12)
        tree=ttk.Treeview(w,columns=('host',),show='headings',selectmode='browse')
        tree.heading('host',text=f'{len(hosts)} subdomínios de {folder.name} — descoberta não confirma disponibilidade')
        tree.pack(fill='both',expand=True,padx=12)
        for host in hosts: tree.insert('','end',values=(host,))
        authorized=tk.BooleanVar(value=False)
        ttk.Checkbutton(w,text='O subdomínio selecionado faz parte do meu escopo autorizado',variable=authorized).pack(pady=8)
        def analyze():
            if self.running or self.brute_running:
                return messagebox.showinfo('Execução','Aguarde a análise atual terminar.',parent=w)
            selected=tree.selection()
            if not selected or not authorized.get():
                return messagebox.showwarning('Escopo','Selecione um subdomínio e marque a autorização.',parent=w)
            host=tree.item(selected[0],'values')[0]
            self.target.set('https://'+host)
            # Credentials for the previous host must not cross host boundaries.
            self.auth_mode.set('Sem login'); self.session_cookie.set(''); self.auth_secret.set('')
            self.auth_user.set(''); self.auth_pass.set(''); self.login_url.set('')
            w.destroy(); self.start()
        ttk.Button(w,text='Analisar selecionado',command=analyze,style='Start.TButton').pack(pady=10)
    def toggle_wordlist(self):
        state='normal' if self.use_wordlist.get() else 'disabled'
        self.wordlist_entry.configure(state=state)
        self.wordlist_button.configure(state=state)

    def browse_wl(self):
        p=filedialog.askopenfilename(initialdir='/usr/share/wordlists')
        if p: self.brute_wordlist.set(p)
    def import_pw(self):
        p=filedialog.askopenfilename()
        if p:
            self.brute_pw.delete('1.0','end'); self.brute_pw.insert('end',Path(p).read_text(errors='ignore')[:200000])

    def sel_phases(self):
        w=tk.Toplevel(self.root); w.title('Fases'); w.configure(bg=BG); w.geometry('380x620')
        vs={}
        selected=self.selected_phases()
        for n,nm in PHASES:
            v=tk.BooleanVar(value=n in selected); vs[n]=v
            tk.Checkbutton(w,text=f'{n:02d}   {nm}',variable=v,bg=BG,fg=FG,activebackground=BG,
                           selectcolor=PANEL,anchor='w',font=(self.F,9)).pack(fill='x',padx=14,pady=1)
        r=tk.Frame(w,bg=BG); r.pack(fill='x',pady=10,padx=14)
        ttk.Button(r,text='Essenciais',command=lambda:[v.set(n in ESSENTIAL) for n,v in vs.items()]).pack(side='left')
        ttk.Button(r,text='Todas',command=lambda:[v.set(True) for v in vs.values()]).pack(side='left',padx=6)
        def apply():
            selected={n for n,v in vs.items() if v.get()}
            if not selected: return messagebox.showwarning('Fases','Selecione ao menos uma fase.',parent=w)
            self.phase_sel=selected; self.custom_phases=True
            for n in self.phase_rows: self.tree.set(self.phase_rows[n],'s','Selecionada' if n in self.phase_sel else 'Ignorada')
            w.destroy()
        ttk.Button(r,text='Aplicar',style='Start.TButton',command=apply).pack(side='right')

    def selected_phases(self):
        if self.custom_phases: return set(self.phase_sel)
        return set(ESSENTIAL) if self.scan_mode.get()=='Rápido' else {n for n,_ in PHASES}

    # ───────────────────── start/stop/poll ─────────────────────
    def start(self):
        if self.running: return
        if self.brute_running: return messagebox.showinfo('Execução','Aguarde os testes de login terminarem.')
        tgt=self.target.get().strip()
        if not tgt: return messagebox.showwarning('Alvo','Informe o domínio.')
        try:
            target_host(tgt if '://' in tgt else 'https://'+tgt)
        except ValueError as exc:
            return messagebox.showwarning('Alvo',str(exc))
        sc=self.script.get()
        if not Path(sc).exists(): return messagebox.showerror('Script',f'Não encontrado: {sc}')
        args=['bash',sc,tgt,'--mode',{'Rápido':'rapido','Completo':'completo','Profundo':'profundo'}[self.scan_mode.get()]]
        if self.auth_mode.get()=='Sessão do navegador' and not self.session_cookie.get():
            return messagebox.showwarning('Autenticação','Primeiro abra o login no navegador e conclua a autenticação.')
        if self.no_install.get(): args.append('--no-install')
        if self.wordpress.get(): args.append('--wordpress')
        if self.custom_phases: args+=['--phases',' '.join(str(n) for n in sorted(self.phase_sel))]
        m={'HTTP Basic':'basic','Bearer':'bearer','Cookie':'cookie','Sessão do navegador':'cookie'}.get(self.auth_mode.get())
        if m: args+=['--auth',m]
        if m=='basic':
            if self.auth_user.get(): args+=['--user',self.auth_user.get()]
            if self.auth_pass.get(): args+=['--pass',self.auth_pass.get()]
        elif m in ('bearer','cookie'):
            secret=self.session_cookie.get() if self.auth_mode.get()=='Sessão do navegador' else self.auth_secret.get()
            if secret: args+=['--secret',secret]
        if self.tg_enabled.get() and self.tg_token.get(): args+=['--telegram',self.tg_token.get(),'--chat',self.tg_chat.get()]
        # A seleção de wordlist é apenas visual; não é enviada ao executor.
        # Testes de autenticação devem usar contas e casos de teste controlados.
        if self.use_proxychains.get():
            proxy=shutil.which('proxychains4')
            if not proxy:
                return messagebox.showerror('Proxychains ausente','proxychains está selecionado, mas proxychains4 não está instalado. A execução não foi iniciada.')
            args=[proxy]+args
        self.output_dir=str((ROOT/'cyberpm-out'/re.sub(r':\d+$','',re.sub(r'^https?://','',tgt).split('/')[0])).resolve())
        self.out_label.set('Saída: '+self.output_dir)
        self.finished_phases.clear(); self.phase_codes={}; self.current_phase=None; self.stop_requested=False; self.seen_findings=0; self.find_rows={}; self.phase_messages={n:[] for n,_ in PHASES}
        self.skipped_by_user=set(); self.scan_finished=False
        self.progress.configure(maximum=max(len(self.selected_phases()),1)); self.progress['value']=0
        self.progress_text.set(f'0 de {len(self.selected_phases())} fases')
        self.alert_count.set('0'); self.report_btn.configure(state='disabled')
        if hasattr(self,'ftree') and self.ftree.winfo_exists(): self.ftree.delete(*self.ftree.get_children())
        self.log.delete('1.0','end')
        for n in self.phase_rows: self.tree.set(self.phase_rows[n],'s','Pendente')
        self.running=True; self.started=time.time(); self.stop_btn.configure(state='normal'); self.start_btn.configure(state='disabled')
        self.ports_btn.configure(state='disabled',text='Portas: coletando')
        self.status.set('Executando'); self.status_chip.configure(fg=ACCENT)
        self.proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,cwd=str(ROOT),start_new_session=True)
        threading.Thread(target=self.reader,daemon=True).start(); self.root.after(1000,self.tick)

    def reader(self):
        for line in self.proc.stdout: self.events.put(('line',clean(line)))
        self.events.put(('done',self.proc.wait()))

    def phase_action(self,event):
        if self.tree.identify_region(event.x,event.y)!='cell' or self.tree.identify_column(event.x)!='#3':
            return
        row=self.tree.identify_row(event.y)
        phase=next((n for n,item in self.phase_rows.items() if item==row),None)
        if phase is not None:
            self.skip_phase(phase)
        return 'break'

    def skip_phase(self,phase):
        if phase not in self.phase_rows or phase in self.finished_phases:
            return
        if not self.running:
            self.phase_sel=set(self.selected_phases())
            self.phase_sel.discard(phase)
            self.custom_phases=True
            self.tree.set(self.phase_rows[phase],'s','Ignorada na próxima execução')
            return
        control=Path(self.output_dir or '')/'controle'
        if not control.is_dir():
            self.append_log('[AVISO] Aguarde o início das fases para pular.\n')
            return
        try:
            (control/f'pular_{phase}').touch()
        except OSError as exc:
            self.append_log(f'[AVISO] Não foi possível solicitar pulo da fase {phase}: {exc}\n')
            return
        self.tree.set(self.phase_rows[phase],'s','Pulo solicitado')
        self.append_log(f'[·] Pulo solicitado para a fase {phase}; demais fases continuam.\n')

    def stop(self):
        if not self.proc or self.proc.poll() is not None: return
        self.stop_requested=True
        self.current_phase=None
        self.stop_brute()
        self.status.set('Interrompendo…')
        self.stop_btn.configure(state='disabled')
        self.progress_text.set('Interrompendo processos…')
        proc=self.proc
        # O grupo de processos é independente do PID líder, que pode já ter saído.
        threading.Thread(target=self._force_stop,args=(proc,proc.pid),daemon=True).start()

    def _force_stop(self,proc,pgid):
        try: os.killpg(pgid,signal.SIGTERM)
        except (ProcessLookupError,PermissionError): pass
        try: proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired: pass
        # Filhos podem continuar com stdout aberto mesmo após o shell encerrar.
        try: os.killpg(pgid,signal.SIGKILL)
        except (ProcessLookupError,PermissionError): pass
        try: proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            try: proc.kill()
            except ProcessLookupError: pass
        # O leitor poderá receber EOF; fallback caso algum filho retenha o pipe.
        self.events.put(('stopped_fallback',proc))

    def poll(self):
        try:
            while True:
                k,v=self.events.get_nowait()
                if k=='line':
                    try: self.on_line(v)
                    except Exception as exc:
                        self.append_log(f'[AVISO] Evento ignorado: {exc}\n')
                elif k=='done':
                    try: self.on_done(v)
                    except Exception as exc:
                        self.append_log(f'[AVISO] Atualização após execução falhou: {exc}\n')
                elif k=='login_progress':
                    index,total,result=v
                    self.brute_progress.set(index*100/max(total,1))
                    self.brute_status.set(f"{index}/{total} · {result['result']}")
                elif k=='login_done':
                    self.brute_running=False; self.brute_btn.configure(state='normal')
                    self.brute_status.set('interrompido' if self.brute_stop else 'concluído — consulte o log')
                    try:
                        if self.output_dir:
                            self.report_btn.configure(state='normal')
                            self.open_report(open_browser=False)
                    finally:
                        self.notify_finished('Teste de senhas encerrado',
                            'Interrompido pelo usuário.' if self.brute_stop else 'Tentativas encerradas. Consulte o log para verificar sucesso indicado, bloqueio ou erro.')
                elif k=='stopped_fallback' and self.running and self.proc is v:
                    self.on_done(v.poll() if v.poll() is not None else -15)
        except queue.Empty: pass
        except Exception as exc:
            self.append_log(f'[AVISO] Evento da interface falhou: {exc}\n')
        self.root.after(120,self.poll)

    def tick(self):
        if self.running and self.started:
            e=int(time.time()-self.started); self.elapsed.set(f'{e//3600:02d}:{(e%3600)//60:02d}:{e%60:02d}')
            self.root.after(1000,self.tick)

    def append_log(self, text, tag=None):
        for line in text.splitlines(keepends=True):
            self.log.insert('end', line, tag or log_tag(line))
        self.log.see('end')

    def on_line(self,l):
        if l.startswith('EVENT|'):
            parts=l.split('|',2)
            if len(parts)<3: return
            kind,value=parts[1:]
            if kind=='OUTPUT':
                self.output_dir=value; self.out_label.set('Saída: '+value)
                self.save_prefs()
            elif kind=='TOTAL':
                if not value.strip().isdigit(): return
                self.total_phases=int(value); self.progress.configure(maximum=max(self.total_phases,1))
                self.progress_text.set(f'0 de {self.total_phases} fases')
            elif kind=='START':
                if not value.strip().isdigit(): return
                n=int(value); self.current_phase=n
                if n in self.phase_rows:
                    self.tree.set(self.phase_rows[n],'s','Executando…'); self.tree.see(self.phase_rows[n])
            elif kind=='STATUS':
                fields=value.split('|')
                if len(fields)==2 and all(field.isdigit() for field in fields):
                    self.phase_codes[int(fields[0])]=int(fields[1])
            elif kind=='SKIPPED':
                if value.strip().isdigit():
                    if not hasattr(self,'skipped_by_user'): self.skipped_by_user=set()
                    self.skipped_by_user.add(int(value))
            elif kind=='END':
                if not value.strip().isdigit():
                    self.append_log(f'[AVISO] END inválido ignorado: {value}\n')
                    return
                n=int(value); self.finished_phases.add(n); self.current_phase=None
                if n==2: self.refresh_ports()
                if n in (6,27): self.secrets_refresh()
                code=self.phase_codes.get(n,0)
                if n in self.phase_rows: self.tree.set(self.phase_rows[n],'s','Pulada pelo usuário' if n in getattr(self,'skipped_by_user',set()) else 'Executada' if code==0 else 'Não executada' if code==3 else f'Falha/parcial ({code})')
                self.progress['value']=min(len(self.finished_phases),self.total_phases)
                self.progress_text.set(f'{len(self.finished_phases)} de {self.total_phases} fases ({100*len(self.finished_phases)//max(self.total_phases,1)}%)')
            elif kind=='FINISH':
                if value.strip() in ('0','1'): self.scan_finished=True
            elif kind=='JS_PROGRESS':
                self.progress_text.set(f'Fase 6 — JavaScript {value} | {len(self.finished_phases)} de {self.total_phases} fases')
            elif kind=='FINDING':
                self.alert_count.set(str(int(self.alert_count.get())+1))
                self.sync_findings()
            return
        self.append_log(l+'\n',log_tag(l)); self.log.see('end')
        if self.current_phase in self.phase_messages:
            messages=self.phase_messages[self.current_phase]
            messages.append(l)
        if FIND_RE.search(l): self.alert_banner.set(l.strip()[:300])
        self.sync_findings()

    def on_done(self,code):
        if not self.running: return
        self.running=False; self.start_btn.configure(state='normal'); self.stop_btn.configure(state='disabled')
        self.refresh_ports()
        stopped=self.stop_requested
        label,title,warning=execution_outcome(code,getattr(self,'scan_finished',False),stopped)
        self.status.set(label)
        self.status_chip.configure(fg=ORANGE if stopped or (code==1 and getattr(self,'scan_finished',False)) else GREEN if code==0 else RED)
        if self.current_phase in self.phase_rows:
            self.tree.set(self.phase_rows[self.current_phase],'s','Interrompida' if stopped else 'Erro')
        self.sync_findings(); self.report_btn.configure(state='normal')
        try:
            report_path=self.open_report(open_browser=False)
            self.append_log( '[RELATÓRIO] Gerado automaticamente: '+str(report_path)+'\n')
            self.send_report_telegram(report_path)
            self.log.see('end')
        except Exception as exc:
            self.append_log( f'[ERRO] Não foi possível gerar relatório: {exc}\n')
        try:
            if hasattr(self,'secrets_refresh'): self.secrets_refresh()
        finally:
            detail=('A execução foi interrompida. Há resultados parciais.' if stopped else
                    'O processamento terminou. Revise os achados e os diagnósticos das fases.' if code==0 else
                    'A execução terminou, com fases parciais ou não executadas. Consulte os diagnósticos e resultados preservados.' if getattr(self,'scan_finished',False) and code==1 else
                    f'O processo terminou com código {code}. Consulte o log e os resultados parciais.')
            self.notify_finished(title,detail,warning=warning)

    def notify_finished(self,title,detail,warning=False):
        try: self.root.bell()
        except tk.TclError: pass
        source='\n\nResultados: '+str(self.output_dir) if self.output_dir else ''
        show=messagebox.showwarning if warning else messagebox.showinfo
        show(title,detail+source,parent=self.root)

    def open_report(self, open_browser=True):
        if not self.output_dir: return messagebox.showinfo('Relatório','Nenhuma execução disponível.')
        base=Path(self.output_dir); base.mkdir(parents=True,exist_ok=True)
        rows=[]; f=base/'achados.tsv'
        if f.exists():
            for line in f.read_text(errors='replace').splitlines():
                p=line.split('\t',4)
                if len(p)==5: rows.append(p)
        tools={'Recon':'whois, RDAP, dig, subfinder, assetfinder, curl/crt.sh', 'Crawl':'gau, waybackurls, katana, ffuf, curl',
               'Arquivos sensíveis':'curl', 'API exposta':'curl', 'Scanner — requer validação':'nuclei',
               'SQLi':'sqlmap', 'XSS':'dalfox', 'Cabeçalhos':'curl', 'CORS':'curl',
               'JavaScript / segredos':'curl, grep', 'Inventário de endpoints JS':'curl, grep', 'Possíveis segredos (não confirmados)':'curl, grep', 'CVE potencial':'nuclei/nmap + grep',
               'IDOR / BOLA':'grep (candidatos; não confirmado)', 'Identificadores':'grep (inventário)'}
        status='Interrompido' if self.stop_requested else self.status.get()
        items=[]
        for sev,asset,cat,msg,evid in rows:
            cells=[report_links(v) for v in
                (classification(sev,cat,msg,evid)[0],sev,asset,cat,msg,tools.get(cat,'Ver evidência da fase'))]
            cells.append(report_path_link(evid,base))
            items.append('<tr>'+''.join('<td>'+v+'</td>' for v in cells)+'</tr>')
        from collections import Counter
        counts=Counter(sev for sev,_,_,_,_ in rows)
        phase_codes=getattr(self,'phase_codes',{})
        successful=sum(code==0 for code in phase_codes.values())
        skipped=sum(code==3 for code in phase_codes.values())
        failed=sum(code not in (0,3) for code in phase_codes.values())
        cards=''.join(f'<div class="metric"><span>{html.escape(label)}</span><strong>{number}</strong></div>' for label,number in (
            ('Fases encerradas',f'{len(self.finished_phases)}/{self.total_phases}'),
            ('Fases processadas sem erro',successful),('Não executadas',skipped),('Falhas/parciais',failed),
            ('Achados registrados',len(rows)),('Críticos',counts.get('CRÍTICO',0)),('Altos',counts.get('ALTO',0))))
        table_rows=''.join(items) or '<tr><td colspan="7" class="empty">Nenhum achado registrado nesta execução.</td></tr>'
        doc=("""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Relatório de varredura</title>
<style>
:root{color-scheme:dark;--bg:#0b0f15;--panel:#151b24;--line:#303846;--text:#e8edf4;--muted:#9ba7b8;--blue:#67a6ff}
*{box-sizing:border-box}body{font:14px/1.6 system-ui,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0}
main{max-width:1500px;margin:auto;padding:32px 24px 80px}header{padding:28px;background:linear-gradient(120deg,#1a2638,#131a24);border:1px solid var(--line);border-radius:16px;margin-bottom:22px}
h1{margin:0 0 8px;font-size:28px;color:#fff}h2{font-size:19px;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
h3{font-size:16px;color:var(--blue);margin:24px 0 8px}h4{font-size:13px;color:#c6d3e5}
.sub{color:var(--muted);margin:0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0 26px}
.metric{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;font-size:25px;margin-top:4px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}table{border-collapse:collapse;width:100%;min-width:1050px}td,th{border-bottom:1px solid var(--line);padding:12px;text-align:left;vertical-align:top;overflow-wrap:anywhere;max-width:420px}th{background:#202b39;color:#bcd0e9;position:sticky;top:0}tr:nth-child(even){background:#111923}.empty{text-align:center;color:var(--muted)}
pre{background:#101722;border:1px solid var(--line);padding:16px;border-radius:10px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:400px;overflow:auto;font-size:12px}
a{color:var(--blue)}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;margin:12px 0}summary{cursor:pointer;color:var(--blue)}.note{color:var(--muted);font-size:12px}
@media print{body{background:white;color:black}header,.metric,pre,details{background:white;color:black}th{color:black;background:#eee}}
</style></head><body><main><header><h1>Relatório de varredura</h1>
<p class="sub">Estado: __STATUS__ · Alvo: __TARGET__ · Gerado em: __DATE__</p></header>
<div class="metrics">__CARDS__</div><h2>Achados e observações</h2>
<p class="note">Classificações automáticas são indicativas e exigem validação manual. Recursos externos não comprovam falhas no alvo.</p>
<div class="table-wrap"><table><thead><tr><th>Classificação</th><th>Severidade</th><th>Ativo</th><th>Categoria</th><th>Descrição</th><th>Ferramenta</th><th>Evidência</th></tr></thead><tbody>__ROWS__</tbody></table></div>
""").replace('__STATUS__',html.escape(status)).replace('__TARGET__',html.escape(self.target.get())).replace('__DATE__',time.strftime('%d/%m/%Y %H:%M:%S')).replace('__CARDS__',cards).replace('__ROWS__',table_rows)
        # Quadro estruturado de registro do domínio, incluído também em relatórios parciais.
        connection=base/'00_conexao'/'estado.json'
        if connection.is_file():
            try:
                health=json.loads(connection.read_text(encoding='utf-8'))
                doc+='<h2>Conectividade antes da varredura</h2><p>'+html.escape(health.get('message',''))+'</p>'
            except (ValueError,OSError):
                doc+='<p>Diagnóstico de conexão indisponível.</p>'
        domain_path=base/'01_recon'/'dominio_dados.json'
        domain_section=['<h2>Informações do domínio — WHOIS / RDAP / DNS</h2>']
        if domain_path.is_file():
            try:
                domain_info=json.loads(domain_path.read_text(encoding='utf-8'))
                fields=domain_info.get('campos',{})
                domain_section.append('<p class="note">Alvo: '+html.escape(str(domain_info.get('alvo','')))+' · Domínio consultado: '+html.escape(str(domain_info.get('dominio_consultado','')) )+'</p>')
                domain_section.append('<div class="table-wrap"><table style="min-width:0"><thead><tr><th>Campo</th><th>Informação disponível</th></tr></thead><tbody>')
                labels=('Nome do titular','Titular / organização','Organização','E-mail cadastrado','E-mail administrativo','E-mail técnico','Telefone cadastrado','Contato de abuso','Contato da registradora','Registradora','País','Criação','Atualização','Expiração','Situação','Nameservers','DNS A','DNS AAAA','DNS MX','DNS NS','DNS TXT','DNS SOA','DNS CNAME','DNS CAA','DNS DS','DNS DNSKEY','DNS HTTPS','DNS TLSA','SPF','DMARC','MTA-STS','TLS-RPT','SOA primário','SOA responsável','IPs públicos','RDAP')
                for label in labels:
                    value=str(fields.get(label,'Não divulgado / não encontrado'))
                    domain_section.append('<tr><td>'+html.escape(label)+'</td><td>'+html.escape(value)+'</td></tr>')
                for label in sorted(k for k in fields if k.startswith('Rede ')):
                    domain_section.append('<tr><td>'+html.escape(label)+'</td><td>'+html.escape(str(fields[label]))+'</td></tr>')
                domain_section.append('</tbody></table></div>')
            except (OSError,ValueError,TypeError) as exc:
                domain_section.append('<p>Não foi possível ler o inventário: '+html.escape(str(exc))+'</p>')
        else:
            domain_section.append('<p class="note">Dados ainda não disponíveis. Execute a Fase 1 para coletar WHOIS, RDAP e DNS.</p>')
        doc+=''.join(domain_section)
        cve_sections=[]
        for _,_,category,message,_ in rows:
            if category=='CVE potencial':
                cve_sections.append('<h3>'+html.escape(message)+'</h3><pre>'+html.escape(cve_guidance(message,self.output_dir))+'</pre>')
        if cve_sections:
            doc+='<h2>CVEs: contexto, reprodução e correção</h2>'+''.join(cve_sections)
        explanations=[]
        for sev,asset,category,message,evidence in rows:
            item=finding_explanation(sev,category,message,evidence)
            explanations.append('<article><h3>'+html.escape(category+' — '+message)+'</h3>')
            for label,value in (
                ('Classificação', item['status']+': '+item['reason']),
                ('O que foi encontrado', item['observation']),
                ('O que pode acontecer', item['impact']),
                ('Como validar ou reproduzir', item['validate']),
                ('Como corrigir', item['fix']),
                ('Como confirmar a correção', item['retest']),
                ('Evidência', item['evidence'])):
                formatted=report_path_link(value,base) if label=='Evidência' else report_links(value)
                explanations.append('<p><strong>'+label+':</strong> '+formatted+'</p>')
            explanations.append('</article>')
        doc+='<h2>Explicação dos resultados</h2>'+(''.join(explanations) or '<p>Nenhum achado registrado. Isso não comprova ausência de falhas; consulte a cobertura e as fases incompletas abaixo.</p>')
        inventory=['<h2>Inventário por fase</h2><p>Resultados informativos não representam, por si só, vulnerabilidades.</p>']
        saved_states={}
        status_path=base/'fases_status.tsv'
        if status_path.is_file():
            with status_path.open(encoding='utf-8',errors='replace',newline='') as stream:
                for record in csv.DictReader(stream,delimiter='\t'):
                    if str(record.get('Fase','')).isdigit():
                        saved_states[int(record['Fase'])]=record
        for n,name in PHASES:
            data=self.phase_data(n,limit=None)
            logs=getattr(self,'phase_messages',{}).get(n,[])
            inventory.append(f'<h3>Fase {n:02d} — {html.escape(name)}</h3><p>Ferramentas: {html.escape(self.PHASE_TOOLS.get(n,"Consultar logs"))}</p>')
            record=saved_states.get(n)
            if record:
                labels={'processada':'Processada; revisar a cobertura nas evidências','erro_ou_parcial':'Falha ou resultado parcial','nao_executada':'Não executada','nao_executada_sem_conexao':'Não executada por falta de resposta HTTP','pulada_pelo_usuario':'Pulada pelo usuário'}
                state=record.get('Estado','')
                inventory.append('<p><strong>Situação:</strong> '+html.escape(labels.get(state,state))+' · '+html.escape(record.get('Duracao_segundos','?'))+' segundos</p>')
            limit_file=base/'controle'/f'limite_{n}.txt'
            if limit_file.is_file():
                inventory.append('<p class="note">'+html.escape(limit_file.read_text(encoding='utf-8',errors='replace'))+'</p>')
            if (base/'controle'/f'pular_{n}').is_file():
                inventory.append('<p class="note">Pulo solicitado pelo usuário. Evidências existentes podem ser parciais.</p>')
            folder=self.PHASE_FILES.get(n,('',[]))[0]
            if folder and (base/folder).is_dir():
                inventory.append('<p>'+report_path_link(folder,base,'Abrir pasta da fase')+'</p>')
            for filename,count,content in data:
                target=self.target.get().strip()
                target=target if target.startswith(('http://','https://')) else 'https://'+target
                formatted=report_links(content,base_url=target if filename=='endpoints.tsv' else None)
                file_link=report_path_link(Path(folder)/filename,base,filename)
                inventory.append(f'<h4>{file_link} — {count} linhas</h4><pre style="white-space:pre-wrap;overflow-wrap:anywhere">{formatted}</pre>')
            if not data:
                inventory.append('<p class="note">Sem resultados salvos para esta fase nesta execução. Isso não comprova ausência de falhas.</p>')
            if logs:
                inventory.append('<details><summary>Log da fase</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'+report_links('\n'.join(logs))+'</pre></details>')
        diagnostics=['<h2>Diagnóstico de execução</h2>']
        for check in sorted((base/'00_conexao').glob('rechecagem_fase_*')):
            if not check.is_dir():
                continue
            diagnostics.append('<h3>Reavaliação da conexão: '+report_path_link(check,base,check.name)+'</h3>')
            for filename in ('estado.json','curl.stderr','curl.exec.txt'):
                path=check/filename
                if path.is_file():
                    diagnostics.append('<h4>'+report_path_link(path,base,filename)+'</h4><pre>'+report_links(path.read_text(encoding='utf-8',errors='replace'))+'</pre>')
        for relative in ('00_conexao/estado.json','00_conexao/curl.stderr','fases_status.tsv','ferramentas.tsv','00_dependencias/status.tsv','20_brute/login_resultados.json','validacao_achados.json'):
            path=base/relative
            if path.is_file():
                diagnostics.append('<h3>'+report_path_link(relative,base)+'</h3><pre style="white-space:pre-wrap">'+report_links(path.read_text(encoding='utf-8',errors='replace'))+'</pre>')
        doc += ''.join(inventory) + ''.join(diagnostics) + '</main></body></html>'
        dest=base/'relatorio.html'; dest.write_text(doc,encoding='utf-8')
        if open_browser:
            self._launch_report(dest)
        return dest

    def send_report_telegram(self, path):
        """Send the generated HTML without blocking the Tkinter event loop."""
        if not self.tg_enabled.get():
            return
        token=self.tg_token.get().strip(); chat=self.tg_chat.get().strip()
        if not token or not chat:
            self.append_log('[TG] Relatório não enviado: configure token e chat ID.\n')
            return
        path=Path(path)
        state='interrompida' if self.stop_requested else 'concluída'
        target=self.target.get().strip()
        def worker():
            try:
                import urllib.request as urlrequest
                import json as jsonlib
                boundary='----PentestReportBoundary'
                def field(name,value):
                    return (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode('utf-8')
                data=(field('chat_id',chat)+field('caption',f'Relatório da varredura {state} — {target}')+
                      f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="relatorio.html"\r\nContent-Type: text/html\r\n\r\n'.encode('utf-8')+
                      path.read_bytes()+f'\r\n--{boundary}--\r\n'.encode('utf-8'))
                request=urlrequest.Request(f'https://api.telegram.org/bot{token}/sendDocument',data=data,
                    headers={'Content-Type':f'multipart/form-data; boundary={boundary}'},method='POST')
                with urlrequest.urlopen(request,timeout=25) as response:
                    result=jsonlib.loads(response.read().decode('utf-8'))
                if not result.get('ok'):
                    raise RuntimeError('API do Telegram não confirmou o envio')
                self.events.put(('line','[TG] Relatório HTML enviado com sucesso.'))
            except Exception as exc:
                self.events.put(('line',f'[TG] Falha ao enviar relatório HTML: {exc}'))
        threading.Thread(target=worker,daemon=True).start()

    def _launch_report(self, dest):
        """Open the HTML report without blocking Tkinter; report failures visibly."""
        import webbrowser
        uri = dest.resolve().as_uri()
        try:
            # xdg-open uses the configured Linux desktop browser.
            if os.name == 'posix' and shutil.which('xdg-open'):
                subprocess.Popen(['xdg-open', uri], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
                self.status.set('Relatório aberto no navegador')
                return
            if webbrowser.open(uri, new=2):
                self.status.set('Relatório aberto no navegador')
                return
        except Exception as exc:
            detail = str(exc)
        else:
            detail = 'Nenhum navegador padrão respondeu ao comando.'
        messagebox.showwarning('Relatório HTML',
            f'O relatório foi salvo, mas não foi possível abrir o navegador.\n\n'
            f'Arquivo: {dest}\n\nDetalhes: {detail}\n\n'
            'Abra o arquivo manualmente no navegador.')

    # ───────────────────── achados ─────────────────────
    def open_findings(self):
        if getattr(self,'find_win',None) and self.find_win.winfo_exists(): self.find_win.lift(); return
        w=tk.Toplevel(self.root); w.title('Achados'); w.geometry('1040x660'); w.configure(bg=BG); self.find_win=w
        tk.Label(w,textvariable=self.alert_banner,bg=PANEL2,fg=FG,font=(self.F,10,'bold'),anchor='w',padx=14,pady=10).pack(fill='x')
        pw=ttk.Panedwindow(w,orient='vertical'); pw.pack(fill='both',expand=True,padx=10,pady=10)
        top=tk.Frame(pw,bg=BG); bot=tk.Frame(pw,bg=BG); pw.add(top,weight=3); pw.add(bot,weight=3)
        self.ftree=ttk.Treeview(top,columns=('sev','cat','msg'),show='tree headings')
        self.ftree.heading('#0',text='Ativo'); self.ftree.column('#0',width=180)
        for col,t,wd in (('sev','Gravidade',120),('cat','Categoria',200),('msg','Achado',640)):
            self.ftree.heading(col,text=t); self.ftree.column(col,width=wd)
        for s,c in SEV_COLOR.items(): self.ftree.tag_configure(s,foreground=c)
        self.ftree.tag_configure('asset',foreground=ACCENT,font=(self.F,10,'bold'))
        sb=ttk.Scrollbar(top,orient='vertical',command=self.ftree.yview); self.ftree.configure(yscrollcommand=sb.set); sb.pack(side='right',fill='y')
        self.ftree.pack(side='left',fill='both',expand=True); self.ftree.bind('<<TreeviewSelect>>',self.show_detail)
        self.detail=tk.Text(bot,wrap='word',bg='#0b0e13',fg=FG,font=('Monospace',10),relief='flat',
                            highlightthickness=1,highlightbackground=BORDER)
        ds=ttk.Scrollbar(bot,orient='vertical',command=self.detail.yview); self.detail.configure(yscrollcommand=ds.set); ds.pack(side='right',fill='y')
        self.detail.pack(side='left',fill='both',expand=True)
        self.sync_findings(force=True)

    def sync_findings(self,force=False):
        if not self.output_dir or not hasattr(self,'ftree') or not self.ftree.winfo_exists(): return
        f=Path(self.output_dir)/'achados.tsv'
        if not f.exists(): return
        try: lines=f.read_text(errors='ignore').splitlines()
        except Exception: return
        if len(lines)<=self.seen_findings and not force: return
        if force: self.ftree.delete(*self.ftree.get_children()); self.find_rows={}; self.seen_findings=0
        for line in lines[self.seen_findings:]:
            p=line.split('\t')
            if len(p)<5: continue
            sev,asset,cat,msg,evid=p[:5]
            node=self.find_rows.get(asset)
            if not node:
                node=self.ftree.insert('','end',text=asset,values=('','',asset),tags=('asset',),open=True); self.find_rows[asset]=node
            it=self.ftree.insert(node,'end',values=(sev,cat,msg),tags=(sev,)); self.find_rows[it]=evid
        self.seen_findings=len(lines)

    def show_detail(self,_e=None):
        sel=self.ftree.selection()
        if not sel: return
        it=sel[0]
        if self.ftree.get_children(it): return
        sev,cat,msg=self.ftree.item(it,'values'); evid=self.find_rows.get(it,''); ex,fix=know(cat,msg)
        self.detail.delete('1.0','end')
        item=finding_explanation(sev,cat,msg,evid)
        status,explanation=item['status'],item['reason']
        self.detail.insert('end',f'CLASSIFICAÇÃO: {status}\nMOTIVO: {explanation}\nGRAVIDADE ORIGINAL: {sev}\nCATEGORIA: {cat}\nACHADO: {msg}\nFERRAMENTA: {TOOLS_BY_CATEGORY.get(cat,"Consultar log da fase")}\nEVIDÊNCIA: {evid}\n')
        self.detail.insert('end','\n── O QUE PODE ACONTECER ──\n'+item['impact']+'\n')
        self.detail.insert('end','\n── COMO VERIFICAR / FERRAMENTA ──\n'+ex+'\n\n── COMO CORRIGIR ──\n'+fix+'\n\n── CONTEÚDO DA EVIDÊNCIA ──\n'+self.preview(evid))
        if cat=='CVE potencial':
            context=cve_guidance(msg,self.output_dir)
            self.detail.insert('1.0',context+'\n')

    def preview(self,path):
        if not path: return '(sem arquivo)'
        p=Path(path)
        if p.is_dir():
            try: return '\n'.join(sorted(x.name for x in p.iterdir())[:100])
            except Exception: return '(pasta)'
        if p.is_file():
            try: return clean(p.read_text(errors='ignore')[:20000])
            except Exception: return '(não legível)'
        return '(não encontrado)'

    # ───────────────────── JS & segredos ─────────────────────
    def open_php_scan(self):
        from php_cve_window import open_window
        window=getattr(self,'php_scan_window',None)
        if window is not None and window.winfo_exists():
            window.lift(); return
        self.php_scan_window=open_window(self.root)

    def open_php2shell(self):
        from php2shell import open_window
        window=getattr(self,'php2shell_window',None)
        if window is not None and window.winfo_exists():
            window.lift(); return
        self.php2shell_window=open_window(self.root,self.target.get().strip())

    def open_secrets(self):
        if getattr(self,'sec_win',None) and self.sec_win.winfo_exists(): self.sec_win.lift(); self.secrets_refresh(); return
        w=tk.Toplevel(self.root); w.title('JS & Segredos'); w.geometry('1040x640'); w.configure(bg=BG); self.sec_win=w
        bar=tk.Frame(w,bg=BG); bar.pack(fill='x',pady=8,padx=10)
        ttk.Button(bar,text='↻ Atualizar',style='Accent.TButton',command=self.secrets_refresh).pack(side='left')
        ttk.Button(bar,text='Copiar valor',command=self.copy_secret_value).pack(side='left',padx=6)
        ttk.Button(bar,text='Copiar detalhes',command=lambda:self.copy_panel(widget=self.sdetail)).pack(side='left')
        self.secrets_count=tk.StringVar(value='Aguardando resultados')
        tk.Label(bar,textvariable=self.secrets_count,bg=BG,fg=FG).pack(side='left',padx=12)
        pw=ttk.Panedwindow(w,orient='horizontal'); pw.pack(fill='both',expand=True,padx=10,pady=(0,10))
        left=tk.Frame(pw,bg=BG); right=tk.Frame(pw,bg=BG); pw.add(left,weight=2); pw.add(right,weight=3)
        self.stree=ttk.Treeview(left,columns=('t','v'),show='headings'); self.stree.heading('t',text='Tipo'); self.stree.heading('v',text='Valor / Arquivo')
        self.stree.column('t',width=160); self.stree.column('v',width=400)
        self.stree.tag_configure('sec',foreground=ORANGE); self.stree.tag_configure('ep',foreground=BLUE)
        sb=ttk.Scrollbar(left,orient='vertical',command=self.stree.yview); self.stree.configure(yscrollcommand=sb.set); sb.pack(side='right',fill='y')
        self.stree.pack(side='left',fill='both',expand=True); self.stree.bind('<<TreeviewSelect>>',self.show_secret)
        self.sdetail=tk.Text(right,wrap='word',exportselection=False,bg='#0b0e13',fg=FG,font=('Monospace',10),relief='flat',
                             highlightthickness=1,highlightbackground=BORDER)
        ds=ttk.Scrollbar(right,orient='vertical',command=self.sdetail.yview); self.sdetail.configure(yscrollcommand=ds.set); ds.pack(side='right',fill='y')
        self.sdetail.pack(side='left',fill='both',expand=True)
        self.secrets_refresh()

    def secrets_refresh(self):
        if not hasattr(self,'stree'): return
        if not self.stree.winfo_exists(): return
        self.stree.delete(*self.stree.get_children())
        self.secret_locations={}; self.secret_values={}
        if hasattr(self,'secrets_count'): self.secrets_count.set('Nenhuma execução atual selecionada')
        if hasattr(self,'sdetail') and self.sdetail.winfo_exists(): self.sdetail.delete('1.0','end')
        if not self.output_dir: return
        base=Path(self.output_dir)
        self.secret_values={}
        rows=secret_rows(base)
        for row in rows:
            filename,line,column,url=(row[key] for key in ('source','line','column','url'))
            location=filename+(':'+line if line else '')+(':'+column if column else '')
            item=self.stree.insert('','end',values=(f"CANDIDATO {row['type']}",row['value']+' · '+location),tags=('sec',))
            self.secret_locations[item]=(filename,line,column,url)
            self.secret_values[item]=row['value']
        if hasattr(self,'secrets_count'):
            self.secrets_count.set(f'{len(rows)} candidato(s) encontrado(s) na execução atual')
        ep=base/'29_js'/'endpoints.tsv'
        if ep.exists():
            for l in ep.read_text(errors='ignore').splitlines()[1:]:
                p=l.split('\t')
                if len(p)>=2: self.stree.insert('','end',values=('ENDPOINT',p[0]),tags=('ep',))
        cont=base/'05_exposicao'/'conteudo'
        if cont.exists():
            for x in sorted(cont.iterdir()): self.stree.insert('','end',values=('ARQUIVO',str(x)))

    def copy_secret_value(self):
        selected=self.stree.selection()
        if not selected: return
        item=selected[0]
        value=getattr(self,'secret_values',{}).get(item)
        if value is None:
            values=self.stree.item(item,'values')
            value=values[1] if len(values)>1 else ''
        if value:
            write_text(self.root,value)
        return 'break'

    def show_secret(self,_e=None):
        if not hasattr(self,'stree') or not self.stree.winfo_exists(): return
        if not hasattr(self,'sdetail') or not self.sdetail.winfo_exists(): return
        sel=self.stree.selection()
        if not sel: return
        v=self.stree.item(sel[0],'values'); self.sdetail.delete('1.0','end')
        location=getattr(self,'secret_locations',{}).get(sel[0])
        if location:
            filename,line,column,url=location
            path=Path(self.output_dir)/filename
            value=getattr(self,'secret_values',{}).get(sel[0],v[1])
            self.sdetail.insert('end',f'{v[0]}\n\nArquivo coletado: {path}\nLinha: {line or "não disponível"}\nColuna: {column or "não disponível em auditorias antigas"}\nURL de origem: {url or "consulte 29_js/manifest.tsv"}\n\nValor encontrado: {value}\n\nOs valores são exibidos completos nas novas coletas. Abra o arquivo coletado no editor e vá à linha/coluna indicada para revisar o candidato.\n\nPara corrigir, altere o código-fonte ou a configuração que gerou esse arquivo e publique novamente o site. Apagar a cópia baixada não remove a exposição no servidor. Se for uma credencial real exposta, revogue/substitua também a credencial. Nomes de campos, exemplos e textos de formulário podem ser falsos positivos.')
            return
        self.sdetail.insert('end', self.preview(v[1]) if v[0]=='ARQUIVO' else f'{v[0]}\n{v[1]}')

    # ───────────────────── anonimato (métodos) ─────────────────────
    def _root(self): return ['pkexec'] if shutil.which('pkexec') else ['sudo']
    def anon_detect(self):
        try:
            o=subprocess.run(['ip','route','get','1.1.1.1'],capture_output=True,text=True).stdout
            m=re.search(r'dev (\S+)',o)
            if m: self.anon_iface.set(m.group(1))
        except Exception: pass
    def iface(self):
        if not self.anon_iface.get().strip(): self.anon_detect()
        value=self.anon_iface.get().strip()
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',value) or value=='lo':
            raise ValueError('Informe uma interface válida, diferente de lo.')
        return value
    def anon_run(self,cmd,label,root=False):
        if root and (self.running or self.brute_running):
            return messagebox.showinfo('Rede em uso','Aguarde ou interrompa a auditoria antes de alterar Tor, AnonSurf ou a interface de rede.')
        full=(self._root() if root else [])+cmd
        self.append_log(f'\n[ANON] {label}: $ {" ".join(full)}\n'); self.log.see('end')
        def w():
            try:
                p=subprocess.run(full,capture_output=True,text=True,timeout=180)
                for ln in ((p.stdout or '')+(p.stderr or '')).splitlines(): self.events.put(('line',f'[ANON] {ln}'))
                self.events.put(('line',f'[ANON] {label}: código de saída {p.returncode}'))
            except Exception as e: self.events.put(('line',f'[ANON] erro: {e}'))
        threading.Thread(target=w,daemon=True).start()
    def anon_check(self):
        try: i=shlex.quote(self.iface())
        except ValueError as exc: return messagebox.showwarning('Rede',str(exc))
        self.anon_run(['bash','-lc',f'ip -br addr show {i}; echo; curl -s --max-time 10 https://ifconfig.me; echo'],'IP/MAC')
    def network_action(self,action,label):
        try: interface=self.iface()
        except ValueError as exc: return messagebox.showwarning('Rede',str(exc))
        self.anon_run([sys.executable,str(ROOT/'network_review.py'),action,interface],label,True)
    def anon_mac(self):
        self.network_action('random','trocar MAC')
    def anon_mac_restore(self):
        self.network_action('restore','MAC original')
    def anon_ip(self):
        self.network_action('renew','renovar IP local por DHCP')

    # ───────────────────── força bruta ─────────────────────
    def detect_api(self):
        self.login_help()

    def brute_force(self):
        if self.brute_running: return
        if self.running: return messagebox.showinfo('Login','Aguarde a varredura atual terminar.')
        url=self.brute_url.get().strip()
        if not url: return messagebox.showwarning('Força bruta','Informe a URL de login.')
        username=self.brute_user.get().strip()
        if not username: return messagebox.showwarning('Login','Informe a conta de teste.')
        try:
            target=self.target.get().strip()
            base=target if target.startswith(('http://','https://')) else 'https://'+target
            if target_host(url)!=target_host(base): raise ValueError('URL de login deve pertencer ao host informado em Alvo.')
            extra=json.loads(self.login_extra.get())
            if not isinstance(extra,dict): raise ValueError('Campos extras devem ser um objeto JSON.')
            if not self.login_user_field.get().strip() or not self.login_password_field.get().strip(): raise ValueError('Informe os nomes dos campos de usuário e senha.')
        except (ValueError,TypeError) as exc:
            return messagebox.showwarning('Configuração de login',str(exc))
        pws=[p for p in self.brute_pw.get('1.0','end').splitlines() if p.strip()]
        if self.use_wordlist.get():
            try:
                with Path(self.brute_wordlist.get()).open(errors='replace') as stream:
                    for line_number,line in enumerate(stream):
                        if len(pws)>=50 or line_number>=500: break
                        value=line.rstrip('\r\n')
                        if value and value not in pws: pws.append(value)
            except OSError as exc:
                return messagebox.showwarning('Wordlist',str(exc))
        if not pws: return messagebox.showwarning('Força bruta','Informe ao menos uma senha.')
        if len(pws)>50: return messagebox.showwarning('Login','Use até 50 senhas da conta de teste por execução.')
        config={'user_field':self.login_user_field.get().strip(),'password_field':self.login_password_field.get().strip(),
                'fmt':self.login_format.get(),'marker':self.login_marker.get(),'csrf_field':self.login_csrf.get().strip(),'extra':extra}
        scan_directory=ROOT/'cyberpm-out'/target_host(base)
        if not self.output_dir or Path(self.output_dir).name!=target_host(base):
            self.output_dir=str(scan_directory); self.finished_phases.clear(); self.current_phase=None
            self.save_prefs(); self.out_label.set('Saída: '+self.output_dir)
        output=Path(self.output_dir)/'20_brute'
        self.brute_running=True; self.brute_stop=False; self.brute_btn.configure(state='disabled')
        self.brute_progress.set(0)
        threading.Thread(target=self._brute_worker,args=(url,username,pws,config,output),daemon=True).start()

    def _brute_worker(self,url,username,pws,config,output):
        rows=[]; total=len(pws)
        try:
            for index,password in enumerate(pws,1):
                if self.brute_stop: break
                result=check_login(url,username,password,**config)
                rows.append({'attempt':index,**result})
                self.events.put(('login_progress',(index,total,result)))
                self.events.put(('line',f"[LOGIN] Tentativa {index}: HTTP {result['status']} · {result['result']} · {result['detail']}"))
                if output:
                    output.mkdir(parents=True,exist_ok=True)
                    (output/'login_resultados.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
                if result['result'] in ('sucesso indicado','bloqueado','erro','revisar configuração'): break
                for _ in range(10):
                    if self.brute_stop: break
                    time.sleep(0.1)
        except Exception as e:
            self.events.put(('line','[LOGIN] Falha interna; configuração ou gravação indisponível'))
        self.events.put(('login_done',None))

    def stop_brute(self): self.brute_stop=True

    def test_tg(self):
        t,c=self.tg_token.get(),self.tg_chat.get()
        if not t or not c: return messagebox.showinfo('Telegram','Informe token e chat id.')
        def w():
            try:
                import urllib.request as u, urllib.parse as up
                d=up.urlencode({'chat_id':c,'text':'Cyberpm v'+APP_VERSION+' — teste Telegram ✓'}).encode()
                u.urlopen(f'https://api.telegram.org/bot{t}/sendMessage',d,timeout=10)
                self.events.put(('line','[TG] enviado ✓'))
            except Exception as e: self.events.put(('line',f'[TG] erro: {e}'))
        threading.Thread(target=w,daemon=True).start()

    def close(self):
        self.brute_stop=True
        if self.proc:
            try: os.killpg(os.getpgid(self.proc.pid),signal.SIGINT)
            except Exception: pass
        self.root.destroy()

if __name__=='__main__':
    root=tk.Tk(); Cyberpm(root); root.mainloop()
