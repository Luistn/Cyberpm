"""In-app CTF handbook opened with F1."""
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText


MANUAL = '''CYBERPM · MANUAL COMPLETO DA BANCADA CTF

ATALHOS
F1       Abrir este manual completo.
Ctrl+D   Abrir o terminal de ajuda DeepSeek.
Ctrl+Enter Enviar uma pergunta ao DeepSeek.

1. FLUXO GERAL
1) Abra CTF na barra lateral.
2) Clique Importar CTF externo · arquivo, URL ou pacote de laboratório.
3) Para um desafio baixado em ZIP, selecione o ZIP inteiro. Não precisa extrair antes: o CyberPM extrai o conteúdo para a pasta de importações e lista os arquivos.
4) O sistema escolhe automaticamente o arquivo mais relevante quando reconhece os pacotes conhecidos. Ele abre CTF → Arquivos e executa a primeira inspeção.
5) Leia o enunciado e o passo a passo na janela de importação. Para escolher outro arquivo, selecione-o na lista e use Usar arquivo na ferramenta.
6) Use a saída destacada. Salvar saída… grava o resultado. Copie a flag completa, incluindo o prefixo e as chaves delimitadoras exigidas pelo desafio.

2. SELECIONE A FERRAMENTA PELA EVIDÊNCIA
PCAP/PCAPNG      Capturas: DNS, filtros ou conversa TCP; Wireshark para inspeção visual.
Texto Base64/hex Codificação: escolha a conversão e clique Converter.
Imagem/binário   Arquivos: assinatura, SHA-256, strings e metadados.
Log              Logs: filtro literal e agrupamento de eventos.
Serviço de rede  Portas: Nmap no host/portas do laboratório.
Aplicação web    Web e sessão: curl, cookie e operações de teste indicadas pelo desafio.

3. OS TRÊS PACOTES DESTE LABORATÓRIO

crazyx0r.zip · reversão do XOR dinâmico
1) Importe o ZIP inteiro; não extraia manualmente.
2) O CyberPM seleciona main.py e executa Resolver XOR crazyx0r automaticamente. Também pode clicar esse botão em CTF → Arquivos.
3) A ferramenta lê o código sem executá-lo, encontra a constante a e o Base64 de flag.txt e calcula candidatos para b e c.
4) Examine os candidatos destacados. Se nenhum formar a flag esperada, confirme que main.py e flag.txt são do mesmo pacote e abra Ver comando / código ou pergunte ao DeepSeek (Ctrl+D).
5) Não use apenas a operação XOR de um byte da aba Codificação: este desafio repete uma chave decimal derivada dos parâmetros.

turtles3crets.zip · imagem com dado oculto
1) Importe o ZIP inteiro. O CyberPM abre Tartaruga.jpg em CTF → Arquivos e mostra strings/metadados.
2) Confira a saída por uma linha Senha:; o botão Extrair dados da imagem procura essa senha automaticamente.
3) Se steghide não estiver instalado no Kali, aceite a instalação do sistema quando o CyberPM oferecer e autentique na janela do sistema. Depois a extração é repetida.
4) Se a extração terminar sem criar o arquivo .extraido, confira se o ZIP correto foi importado, se a senha foi lida inteira e se a saída do steghide informa dados incorporados.
5) Quando a extração gerar um arquivo, o CyberPM o seleciona e inspeciona automaticamente. Se o conteúdo for outro arquivo compactado, importe esse arquivo também e siga o mesmo fluxo.

broken.zip · análise do executável ELF
1) Importe o ZIP inteiro. O executável br0k3n é encaminhado para CTF → Arquivos; confira a assinatura ELF e as strings.
2) Clique Analisar binário com GDB. A análise consulta funções e desmonta main, gerar_chave_secreta e revelar_flag; ela não executa o binário.
3) Se gdb não estiver instalado no Kali, aceite a instalação e autentique. O CyberPM repete a análise após a instalação.
4) Na saída, relacione os nomes de funções e as comparações da chave com as mensagens visíveis nas strings. Se precisar observar o programa em execução, faça isso somente no Kali isolado do CTF; o botão automatizado evita executar binários desconhecidos.
5) Se o GDB disser que não conhece uma função, use info functions para conferir o nome exato e revise strings e disassembly. Pergunte ao DeepSeek com a saída selecionada na conversa.

4. QUANDO ALGO DER ERRADO
• ZIP não abre: tente novamente selecionando o ZIP original; confira o limite de extração (512 MiB padrão) e se o arquivo não está incompleto.
• Arquivo errado foi aberto: volte à janela Importar CTF externo, selecione o arquivo certo e clique Usar arquivo na ferramenta.
• Saída vazia ou sem flag: confira o arquivo selecionado, leia as mensagens do programa e compare os arquivos relacionados do pacote. Uma análise inicial pode mostrar só uma pista.
• Ferramenta ausente: no Kali/Debian, aceite a janela de instalação e autentique. A instalação automática requer apt-get e pkexec. Em outros sistemas, instale a ferramenta no ambiente que executa o CyberPM.
• Erro de senha/extração: confira espaços, símbolos e maiúsculas. Não remova pontuação da senha. Leia a mensagem completa do steghide antes de tentar de novo.
• Saída grande: role o painel ou use Salvar saída… e abra o arquivo salvo num editor.
• Não sabe o próximo passo: Ctrl+D abre o terminal DeepSeek. Cole a dúvida; o contexto atual do CyberPM é enviado junto com a pergunta.

5. ASSISTENTE DEEPSEEK
Ctrl+D abre o assistente. Cole sua chave API e escolha Salvar chave. A chave é guardada na configuração local do usuário, fora do repositório. Digite uma pergunta e pressione Ctrl+Enter. A aba CTF e a saída atual são anexadas como contexto. A conversa fica apenas nesta sessão; Nova conversa limpa o histórico.

6. SAÍDAS E DADOS
Flags CTF reconhecidas e candidatos do XOR aparecem destacados. Salvar saída… exporta o texto visível. Pacotes importados ficam em ~/.config/cyberpm/ctf-imports. Não envie evidências privadas nem dados de sessão ao assistente se não quiser compartilhá-los com o serviço de API.
'''


def open_ctf_manual(parent):
    window = tk.Toplevel(parent)
    window.title('Cyberpm · Manual completo do CTF')
    window.geometry('1000x850')
    window.minsize(760, 600)
    frame = ttk.Frame(window, padding=12)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='Manual completo para usar a bancada CTF',
              font=('TkDefaultFont', 15, 'bold')).pack(anchor='w', pady=(0, 8))
    text = ScrolledText(frame, wrap='word', font=('TkFixedFont', 10), padx=10, pady=8)
    text.pack(fill='both', expand=True)
    text.insert('1.0', MANUAL)
    text.configure(state='disabled')
    window.transient(parent)
    window.focus_set()
    return window
