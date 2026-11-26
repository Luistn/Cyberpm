"""Run defensive checks against user-selected local artifacts."""
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

TOOLS = (
    ('Semgrep', 'semgrep', 'Diretório de código', True),
    ('Gitleaks', 'gitleaks', 'Diretório de arquivos', True),
    ('Checkov', 'checkov', 'Diretório de infraestrutura', True),
    ('OSV-Scanner', 'osv-scanner', 'Arquivo de dependências', False),
    ('Syft', 'syft', 'Diretório para gerar SBOM', True),
    ('Grype', 'grype', 'Arquivo SBOM', False),
)

TOOL_HELP = {
    'semgrep': 'Encontra problemas no código-fonte com base em regras. Clique em Analisar, escolha a pasta do projeto e depois um arquivo local de regras do Semgrep (.yml ou .yaml). A saída indica o arquivo, a linha e a regra de cada achado.',
    'gitleaks': 'Procura senhas, tokens e chaves nos arquivos da pasta. Clique em Analisar e escolha a pasta do projeto. Confira o arquivo, a linha e o tipo de cada ocorrência. Os valores detectados são mascarados na saída.',
    'checkov': 'Revisa configurações em Dockerfiles, Terraform e Kubernetes. Clique em Analisar e escolha a pasta que contém esses arquivos. Confira as regras que falharam e o arquivo correspondente.',
    'osv-scanner': 'Compara versões de dependências com avisos conhecidos. Clique em Analisar e escolha um arquivo como package-lock.json, poetry.lock ou composer.lock. Confira o pacote, a versão e o identificador do aviso na saída.',
    'syft': 'Cria um SBOM, uma lista dos componentes e versões encontrados. Clique em Gerar SBOM e escolha a pasta do projeto ou do deploy. Quando terminar, clique em Salvar SBOM… para guardar o JSON.',
    'grype': 'Compara os componentes de um SBOM com avisos de vulnerabilidade. Clique em Analisar e selecione o JSON salvo pelo Syft. Confira o pacote, a versão e o aviso de cada correspondência.',
}


def analysis_args(tool, path, rules=None):
    return {
        'semgrep': ['scan', '--metrics=off', '--json', '--config', rules, path],
        'gitleaks': ['dir', '--redact=100', '--no-banner', '--no-color', '--verbose', path],
        'checkov': ['--directory', path, '--framework', 'terraform,kubernetes,dockerfile',
                    '--skip-download', '--output', 'json'],
        'osv-scanner': ['scan', 'source', '--format', 'json', '--lockfile', ':' + path],
        'syft': ['scan', 'dir:' + path, '-o', 'cyclonedx-json'],
        'grype': ['sbom:' + path, '-o', 'json'],
    }[tool]


class LocalAnalysisWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('CyberPM — Análise local')
        self.geometry('920x640')
        ttk.Label(self, text='Escolha uma ferramenta para revisar arquivos do seu projeto. Use Como usar para ver o que selecionar.',
                  padding=(12, 12, 12, 0), wraplength=640).pack(fill='x')
        self.protocol('WM_DELETE_WINDOW', self.withdraw)
        self.run_results = queue.Queue()
        controls = ttk.Frame(self, padding=12)
        controls.pack(fill='x')
        self.buttons = []
        for row, (label, tool, source, directory) in enumerate(TOOLS):
            ttk.Label(controls, text=label).grid(row=row, column=0, sticky='w', padx=(0, 12))
            ttk.Label(controls, text=source).grid(row=row, column=1, sticky='w', padx=(0, 12))
            installed = shutil.which(tool)
            ttk.Label(controls, text='No PATH' if installed else 'Fora do PATH').grid(row=row, column=2, sticky='w')
            button = ttk.Button(controls, text='Analisar' if tool != 'syft' else 'Gerar SBOM',
                                command=lambda tool=tool, directory=directory: self.start(tool, directory))
            button.grid(row=row, column=3, padx=10, pady=2)
            button.state(['!disabled'] if installed else ['disabled'])
            self.buttons.append((tool, button))
            ttk.Button(controls, text='Como usar', command=lambda tool=tool: self.show_help(tool)).grid(
                row=row, column=4, sticky='w', pady=2)
        self.help_text = tk.StringVar(self)
        ttk.Label(self, textvariable=self.help_text, padding=(12, 0, 12, 12), wraplength=640).pack(fill='x')
        self.show_help('syft')
        self.status = tk.StringVar(self)
        ttk.Label(self, textvariable=self.status, padding=(12, 0, 12, 8)).pack(fill='x')
        self.sbom = ''
        self.save_button = ttk.Button(self, text='Salvar SBOM…', command=self.save_sbom, state='disabled')
        self.save_button.pack(anchor='w', padx=12, pady=(0, 8))
        self.output = scrolledtext.ScrolledText(self, wrap='word', state='disabled')
        self.output.pack(fill='both', expand=True, padx=12, pady=(0, 12))

    def show_help(self, tool):
        label = next(label for label, command, _, _ in TOOLS if command == tool)
        availability = '' if shutil.which(tool) else '\nInstale a ferramenta no Kali para habilitar a análise.'
        self.help_text.set(f'{label}\n{TOOL_HELP[tool]}{availability}')

    def start(self, tool, directory):
        executable = shutil.which(tool)
        if not executable:
            self.status.set(f'{tool} não foi encontrado no PATH.')
            return
        picker = filedialog.askdirectory if directory else filedialog.askopenfilename
        selected = picker(parent=self)
        if not selected:
            return
        path = str(Path(selected).absolute())
        rules = None
        if tool == 'semgrep':
            rules = filedialog.askopenfilename(parent=self, title='Selecionar arquivo local de regras do Semgrep')
            if not rules:
                return
        command = [executable, *analysis_args(tool, path, rules)]
        for _, button in self.buttons:
            button.state(['disabled'])
        self.status.set(f'{tool} em execução…')
        threading.Thread(target=self.run_analysis, args=(tool, command), daemon=True).start()
        self.after(150, self.poll_result)

    def run_analysis(self, tool, command):
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                    encoding='utf-8', errors='replace', timeout=300)
            output = '\n'.join(part for part in (result.stdout, result.stderr) if part.strip())
            sbom = result.stdout if tool == 'syft' and result.returncode == 0 else ''
            code = result.returncode
            status = 'Análise concluída.' if code == 0 else f'Processo encerrado com código {code}. Consulte a saída.'
            if tool in ('gitleaks', 'osv-scanner', 'checkov') and code == 1 and output:
                status = 'A ferramenta sinalizou achados ou um erro. Consulte a saída.'
            self.run_results.put((status, output, sbom))
        except subprocess.TimeoutExpired:
            self.run_results.put(('Tempo limite de 300 segundos atingido.', '', ''))
        except OSError as error:
            self.run_results.put((f'Falha ao iniciar a ferramenta. {error}', '', ''))

    def poll_result(self):
        try:
            status, output, sbom = self.run_results.get_nowait()
        except queue.Empty:
            self.after(150, self.poll_result)
            return
        self.status.set(status)
        self.sbom = sbom
        self.save_button.state(['!disabled'] if sbom else ['disabled'])
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', output)
        self.output.configure(state='disabled')
        for tool, button in self.buttons:
            if shutil.which(tool):
                button.state(['!disabled'])

    def save_sbom(self):
        path = filedialog.asksaveasfilename(parent=self, initialfile='inventario.cdx.json', defaultextension='.json')
        if path:
            try:
                Path(path).write_text(self.sbom, encoding='utf-8')
                self.status.set(f'SBOM salvo em {path}')
            except OSError as error:
                self.status.set(f'Falha ao salvar o SBOM. {error}')
