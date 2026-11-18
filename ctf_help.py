"""Tool descriptions, classroom instructions and copyable terminal examples."""
import inspect
import shlex
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from ctf_tools import generate_wordlist, local_file, log_report, save_wordlist
from system_clipboard import write_text


TOOL_GUIDES = {
    'Capturas': (
        'TShark / Wireshark · análise de arquivos PCAP e PCAPNG.',
        'Use quando a missão entregar uma captura de rede.\n\n'
        '1. Baixe e extraia o arquivo do desafio no Kali. Clique em Selecionar e escolha o .pcap. '
        'Para treinar primeiro, clique em Carregar exemplo.\n'
        '2. Para Rastro no DNS, escolha Consultas DNS e clique em Ler com TShark. '
        'Leia os nomes consultados e procure o domínio mencionado na história.\n'
        '3. Para Conversa interceptada, escolha Conversa TCP, índice 0, e execute. '
        'Procure a resposta HTTP e leia o texto depois dos cabeçalhos. '
        'Se a captura tiver outras conversas, consulte os índices no Wireshark.\n'
        '4. Resumo filtrado aceita expressões como http, dns ou tcp.stream == 0. '
        'O filtro escolhe quais pacotes mostrar.\n'
        '5. Copie a evidência solicitada, monte CTF{resposta} e envie no site do CTF. '
        'Ver comando / código mostra as opções para repetir a leitura pelo terminal.'),
    'Codificação': (
        'Python 3 · bibliotecas base64 e bytes; XOR calculado no próprio painel.',
        'Use quando a evidência é um texto codificado ou uma sequência hexadecimal.\n\n'
        '1. Copie somente a mensagem da missão para a caixa de texto.\n'
        '2. Escolha Base64 → texto para decodificar uma mensagem como Q1RGe...; '
        'Hexadecimal → texto aceita pares como 43 54 46.\n'
        '3. Para Chave de um byte, escolha XOR de um byte. Cole os pares hexadecimais e '
        'informe a chave em hexadecimal. No exercício, 69 XOR 43 resulta em 2a.\n'
        '4. Clique em Converter e leia a saída abaixo. Se houver CTF{...}, copie desde CTF até a chave final. '
        'Texto → Base64 e Texto → hexadecimal fazem o caminho de codificação.\n'
        '5. Carregar exemplo acompanha a operação selecionada. Troque a operação e carregue novamente para '
        'ver outro caso. Ver comando / código gera um script Python independente com o texto atual.'),
    'Arquivos': (
        'Python 3 para assinatura, SHA-256 e strings; ExifTool para metadados.',
        'Use quando a missão entregar uma imagem, um .bin ou outro arquivo.\n\n'
        '1. Baixe o arquivo e clique em Selecionar. No exemplo, é usado um PNG com um comentário.\n'
        '2. Clique em Assinatura, hash e strings. O resumo mostra formato identificado, tamanho, '
        'primeiros bytes e o SHA-256 completo. A assinatura ajuda a reconhecer um arquivo mesmo com extensão trocada.\n'
        '3. Leia os trechos de texto e procure o termo da missão ou CTF{. '
        'A lista de strings é uma amostra dos primeiros 2 MB.\n'
        '4. Clique em Metadados ExifTool para ver campos como Comment e datas, quando presentes. '
        'No desafio Além do texto visível, a flag está no comentário PNG.\n'
        '5. Envie a informação pedida. Arquivo disfarçado pede o formato em minúsculas, enquanto '
        'o exercício de metadados pede a flag completa. Ver comando / código mostra os utilitários equivalentes.'),
    'Logs': (
        'Python 3 · filtro literal e agrupamento de eventos ip=, user=, FAIL e OK.',
        'Use quando a missão entregar registros de acesso.\n\n'
        '1. Selecione o arquivo .log. Você pode carregar o exemplo para aprender o formato.\n'
        '2. No filtro, escreva user=aluno para ler somente essa conta. Vazio mostra todas as linhas disponíveis. '
        'O filtro procura texto literal.\n'
        '3. Clique em Filtrar e agrupar. Leia cada grupo de IP e usuário separadamente. '
        'FAIL é falha de autenticação e OK é acesso aceito.\n'
        '4. Na missão Tentativas em série, procure FAIL → FAIL → FAIL → OK. '
        'Confira os horários nas linhas originais e a regra da história. A ordem mostrada segue o arquivo.\n'
        '5. A resposta desse exercício é o IP dentro de CTF{...}. Ver comando / código oferece '
        'um script Python com o mesmo agrupamento para rodar no terminal.'),
    'Portas': (
        'Nmap · conexões TCP nas portas informadas; suporte a IPv4 e IPv6.',
        'Use quando a missão pedir a porta de um serviço.\n\n'
        '1. Se estiver usando o ZIP do CTF, execute python3 servico.py em um terminal do Kali e mantenha-o aberto. '
        'Carregar exemplo inicia um serviço temporário automaticamente neste computador.\n'
        '2. Digite o host ou IP sem http://. Para o laboratório no mesmo Kali, use 127.0.0.1.\n'
        '3. Informe as portas, como 8780-8789 ou 80,443. Clique em Executar Nmap.\n'
        '4. Leia a coluna STATE. open significa que a porta aceitou conexão. Copie o número antes de /tcp.\n'
        '5. Envie CTF{numero}. Na opção de exemplo, a porta é escolhida automaticamente e pode mudar. '
        'Ver comando / código explica -sT, -Pn e -p e mostra o comando com os campos atuais.'),
    'Web e sessão': (
        'curl para HTTP e cookies; SQLmap para SQL injection; Dalfox para XSS; navegador para executar HTML/JS.',
        'Use a URL do laboratório da missão.\n\n'
        '1. Inicie python3 lab.py do ZIP no Kali ou clique em Carregar exemplo. '
        'Para o exemplo, troque a operação e carregue novamente para preencher a rota correspondente.\n'
        '2. Em Resposta e cabeçalhos, use /admin. Execute sem cookie e observe HTTP 403. '
        'Depois digite papel=admin em Cookie e execute. No exemplo local, HTTP 200 acompanha CTF{admin_local}.\n'
        '3. Em SQLmap, use uma URL com parâmetro, como /busca?q=Redes. Clique em Executar e '
        'leia se q foi identificado como injetável. O guia do site mostra como recuperar a flag pelo formulário.\n'
        '4. Em Dalfox (XSS), use /xss?q=teste e revise os resultados. Para executar o JavaScript da missão, '
        'abra o formulário no navegador e envie <script>provarXSS()</script>.\n'
        '5. O campo Cookie aceita o cabeçalho no formato nome=valor; outro=valor. '
        'Ver comando / código mostra a URL e o cookie atuais para repetir o pedido no terminal.'),
    'Gerador de listas': (
        'Python 3 · combina palavras e sufixos e exporta uma wordlist UTF-8 para Hydra ou John.',
        'Use para criar candidatas a senha em um exercício.\n\n'
        '1. Digite uma palavra por linha na caixa Palavras-base. Exemplo: rede e caderno.\n'
        '2. Em Sufixos, coloque uma entrada por linha, como 42 e 2026. '
        'A lista incluirá rede, rede42, rede2026, caderno, caderno42 e caderno2026.\n'
        '3. A opção de maiúsculas acrescenta variantes como REDE e Rede. '
        'Clique em Gerar prévia para ver a quantidade e as primeiras 40 candidatas.\n'
        '4. Clique em Gerar e salvar .txt. Escolha a pasta e o nome do arquivo. '
        'A exportação contém todas as candidatas únicas, até o limite de 50 mil.\n'
        '5. No John, selecione esse arquivo em Lista de palavras. No Hydra, selecione em Wordlist de senhas. '
        'Ver comando / código gera um script independente com as palavras e sufixos atuais.'),
    'Guia e listas': (
        'APT para pacotes Kali; SecLists para coleções de listas; atalhos para John e Hydra.',
        '1. Escolha a ferramenta pela evidência. PCAP usa Capturas, texto codificado usa Codificação, '
        'imagem/binário usa Arquivos e eventos de acesso usam Logs.\n'
        '2. Se um programa estiver ausente, selecione seu pacote e clique em Instalar pacote escolhido. '
        'O Kali poderá pedir autenticação do sistema.\n'
        '3. Após instalar SecLists, procure /usr/share/seclists/Passwords para senhas e '
        '/usr/share/seclists/Discovery/Web-Content para caminhos web.\n'
        '4. John e Hydra abrem em janelas próprias do Cyberpm, também acessíveis pelos atalhos desta aba. '
        'John usa hashes locais; Hydra envia tentativas a um login ativo. Cada janela tem exemplo e comando copiável.\n'
        '5. Para estudar a explicação da missão, abra Histórias e guias. '
        'Resolva a evidência no Cyberpm e envie a flag na página do desafio.'),
}

ACTION_TOOLS = {
    'Ler com TShark': 'TShark lê a captura e extrai os campos ou a conversa selecionada.',
    'Abrir no Wireshark': 'Wireshark abre a captura em uma interface gráfica.',
    'Converter': 'Python 3 processa Base64, hexadecimal ou XOR dentro do painel.',
    'Assinatura, hash e strings': 'Python 3 lê os bytes e calcula SHA-256 e trechos imprimíveis.',
    'Metadados ExifTool': 'ExifTool consulta os campos de metadados do arquivo.',
    'Filtrar e agrupar': 'Python 3 agrupa as linhas do log por IP e usuário.',
    'Executar Nmap': 'Nmap abre conexões TCP no host e portas informados.',
    'Executar': 'Usa a operação selecionada: curl, SQLmap ou Dalfox.',
    'Gerar prévia': 'Python 3 gera candidatas e mostra as primeiras 40.',
    'Gerar e salvar .txt': 'Python 3 grava a lista completa em um arquivo UTF-8.',
    'Carregar exemplo': 'Preenche os campos com um exemplo de aula e explica o próximo passo.',
    'Limpar exemplo e saída': 'Esvazia os campos e a saída desta ferramenta.',
    'Abrir no navegador': 'Abre a URL no navegador padrão do sistema.',
    'Instalar pacote escolhido': 'APT instala o pacote do Kali escolhido, com autenticação do sistema.',
}


class HoverTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.pending = None
        self.popup = None
        widget.bind('<Enter>', self.schedule, add='+')
        widget.bind('<Leave>', self.hide, add='+')
        widget.bind('<ButtonPress>', self.hide, add='+')
        widget.bind('<Destroy>', self.hide, add='+')

    def schedule(self, event=None):
        self.hide()
        self.pending = self.widget.after(450, self.show)

    def show(self):
        self.pending = None
        if not self.widget.winfo_exists():
            return
        self.popup = tk.Toplevel(self.widget)
        self.popup.overrideredirect(True)
        label = tk.Label(self.popup, text=self.text() if callable(self.text) else self.text, background='#fff3b0', foreground='#18212f',
                         justify='left', wraplength=380, padx=10, pady=7, relief='solid', borderwidth=1)
        label.pack()
        self.popup.update_idletasks()
        x = min(self.widget.winfo_rootx(), self.widget.winfo_screenwidth()-self.popup.winfo_reqwidth()-10)
        y = self.widget.winfo_rooty()+self.widget.winfo_height()+5
        if y+self.popup.winfo_reqheight() > self.widget.winfo_screenheight():
            y = self.widget.winfo_rooty()-self.popup.winfo_reqheight()-5
        self.popup.geometry(f'+{max(0,x)}+{max(0,y)}')

    def hide(self, event=None):
        if self.pending is not None:
            self.widget.after_cancel(self.pending)
            self.pending = None
        if self.popup is not None:
            self.popup.destroy()
            self.popup = None


def show_document(parent, title, description, text):
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.geometry('900x650')
    dialog.minsize(600, 400)
    frame = ttk.Frame(dialog, padding=12)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text=description, wraplength=840, justify='left').pack(anchor='w', pady=(0,8))
    output = ScrolledText(frame, wrap='word', font=('Courier', 10))
    output.pack(fill='both', expand=True)
    output.insert('1.0', text)
    output.configure(state='disabled')
    status = tk.StringVar()

    def copy():
        try:
            write_text(dialog, text)
            status.set('Copiado para a área de transferência.')
        except (OSError, tk.TclError) as exc:
            status.set(f'Falha ao copiar: {exc}')

    bar = ttk.Frame(frame)
    bar.pack(fill='x', pady=(8,0))
    ttk.Button(bar, text='Copiar texto', style='CtfRun.TButton', command=copy).pack(side='left')
    ttk.Button(bar, text='Fechar', style='CtfInfo.TButton', command=dialog.destroy).pack(side='left', padx=8)
    ttk.Label(bar, textvariable=status).pack(side='left')
    return dialog


def shell_command(args):
    return shlex.join([str(arg) for arg in args])


def python_script(body):
    return "python3 - <<'PY_CTF'\n" + body.rstrip() + '\nPY_CTF\n'


def conversion_script(text, operation, key):
    from ctf_tools import transform
    body = 'import base64\n\n' + inspect.getsource(transform) + '\n'
    body += f'texto = {text!r}\noperacao = {operation!r}\nchave = {key!r}\n'
    body += 'print(transform(texto, operacao, chave))\n'
    return python_script(body)


def logs_script(path, query):
    body = 'from pathlib import Path\nfrom collections import defaultdict\nimport re\n\n'
    body += inspect.getsource(local_file) + '\n' + inspect.getsource(log_report) + '\n'
    body += f'print(log_report({path!r}, {query!r}))\n'
    return python_script(body)


def wordlist_script(seeds, suffixes, variations):
    body = 'from pathlib import Path\nimport os\nimport tempfile\n\n'
    body += inspect.getsource(generate_wordlist) + '\n' + inspect.getsource(save_wordlist) + '\n'
    body += f'palavras = {seeds!r}\nsufixos = {suffixes!r}\n'
    body += f'lista = generate_wordlist(palavras, sufixos, {variations!r})\n'
    body += "save_wordlist('lista-ctf.txt', lista)\nprint(len(lista), 'candidatas salvas em lista-ctf.txt')\n"
    return python_script(body)


def john_terminal(hashes, words, format_name):
    args = ['john', '--pot=ctf-terminal.pot']
    if format_name.strip():
        args += ['--format='+format_name.strip()]
    run = args + ['--wordlist='+(words or 'PALAVRAS.txt'), hashes or 'HASHES.txt']
    show = args + ['--show', hashes or 'HASHES.txt']
    return shell_command(run) + '\n' + shell_command(show)


def hydra_terminal(target, service, user, words, port, tasks, delay, module, stop_first):
    args = ['hydra', '-l', user or 'USUARIO', '-P', words or 'SENHAS.txt', '-t', tasks or '1',
            '-W', delay or '1', '-v']
    if stop_first:
        args += ['-f']
    if port:
        args += ['-s', port]
    args += [target or '127.0.0.1', service]
    if module:
        args += [module]
    return shell_command(args)
