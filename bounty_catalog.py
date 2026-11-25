"""Trilha Bug Bounty e inventário de evidências locais."""
import shutil
from urllib.parse import unquote_plus, urlsplit

LEVELS = (
    ("Mapear a superfície", (
        ("Encontrar subdomínios", "Subfinder · assetfinder · OWASP Amass",
         "Compare nomes descobertos com a lista de ativos autorizados."),
        ("Resolver e verificar hosts ativos", "dnsx · httpx · naabu",
         "Registre separadamente nomes resolvidos, respostas HTTP e serviços. Consulte as regras do programa sobre sondagem e portas."),
    )),
    ("Coletar URLs, parâmetros e JavaScript", (
        ("Coletar URLs do histórico", "waybackurls · gau · waymore · ParamSpider",
         "Confira se o host de cada URL histórica continua no escopo."),
        ("Navegar pelo site ao vivo", "Katana",
         "Revise os endpoints observados e identifique referências a terceiros."),
        ("Encontrar parâmetros ocultos", "Arjun · ParamSpider",
         "Separe parâmetros observados em arquivos históricos dos que aparecem no tráfego atual."),
        ("Filtrar listas de URLs e JavaScript", "gf · LinkFinder",
         "Use padrões para triagem e revise referências a endpoints em arquivos JavaScript."),
    )),
    ("Triar evidências com IA", (
        ("Analisar evidências com um modelo local", "Ollama",
         "Revise dados sanitizados e confira as conclusões contra a evidência original."),
        ("Usar IA dentro do Burp", "ReconAIzer · BurpGPT · Burp AI",
         "Revise tráfego já capturado. Remova tokens, cookies e dados de clientes antes de usar serviços externos."),
        ("Revisar resultados de scanners por modelos", "Nuclei",
         "Relacione os alertas importados com os ativos autorizados e registre as incertezas."),
    )),
    ("Revisar evidências em escopo", (
        ("Investigar caminhos ocultos", "ffuf",
         "Revise caminhos presentes nos registros e diferencie respostas reais de páginas genéricas."),
        ("Revisar indícios de XSS", "Dalfox",
         "Compare alertas existentes com os controles de codificação de saída no código ou no relatório."),
        ("Capturar a superfície em imagens", "GoWitness",
         "Organize capturas por host e trate imagens de sessões autenticadas como dados privados."),
        ("Revisar registros fora de banda", "Interactsh",
         "Correlacione horário, ativo e registros existentes antes de atribuir uma interação ao aplicativo."),
    )),
    ("Revisar código-fonte e relatórios", (
        ("Conhecer agentes de laboratório", "PentestGPT · hackingBuddyGPT · Strix · Shannon",
         "Referência de ferramentas. Revise relatórios existentes e converta achados em tarefas de correção."),
        ("Analisar um repositório Python", "Vulnhuntr",
         "Revise entradas não confiáveis, controles e fluxos de dados no código. Registre arquivos e linhas relevantes."),
    )),
)


TOOL_DESCRIPTIONS = {
    "Subfinder": "Consulta fontes públicas em busca de subdomínios.",
    "assetfinder": "Consulta fontes públicas para localizar nomes relacionados.",
    "OWASP Amass": "Organiza dados sobre ativos e relações entre domínios.",
    "dnsx": "Consulta registros DNS de nomes conhecidos.",
    "httpx": "Registra respostas e metadados HTTP.",
    "naabu": "Identifica portas que respondem.",
    "waybackurls": "Coleta URLs registradas pelo Internet Archive.",
    "gau": "Reúne URLs conhecidas por diferentes arquivos públicos.",
    "waymore": "Consulta históricos de URLs e respostas arquivadas.",
    "ParamSpider": "Extrai URLs parametrizadas de arquivos públicos.",
    "Katana": "Rastreia links e referências em páginas.",
    "Arjun": "Identifica parâmetros HTTP aceitos por um endpoint.",
    "gf": "Aplica padrões nomeados a listas e arquivos locais.",
    "LinkFinder": "Extrai referências a URLs e endpoints em JavaScript.",
    "Ollama": "Executa modelos de linguagem localmente.",
    "ReconAIzer": "Usa um modelo para sugerir itens de revisão a partir de tráfego no Burp.",
    "BurpGPT": "Adiciona análise com modelo ao tráfego capturado no Burp.",
    "Burp AI": "Oferece assistência de IA para revisar informações no Burp.",
    "Nuclei": "Aplica modelos de verificação e registra alertas.",
    "ffuf": "Faz descoberta de conteúdo por comparação de respostas.",
    "Dalfox": "Identifica possíveis ocorrências de XSS.",
    "GoWitness": "Captura imagens de páginas e reúne os resultados.",
    "Interactsh": "Registra interações de rede fora de banda.",
    "PentestGPT": "Organiza etapas de testes de segurança com um modelo.",
    "hackingBuddyGPT": "Implementa casos de pesquisa sobre agentes de segurança.",
    "Strix": "Usa agentes para avaliar a segurança de aplicações.",
    "Shannon": "Usa código-fonte para orientar testes em uma aplicação.",
    "Vulnhuntr": "Usa um modelo para revisar fluxos de dados em código Python.",
}

INVENTORY_TOOLS = ("subfinder", "assetfinder", "dnsx", "gau", "waybackurls", "gf")


def inventory_tool_status():
    for command in INVENTORY_TOOLS:
        path = shutil.which(command)
        yield f"{command} — {path or 'indisponível no PATH'}"


def summarize_inventory(lines):
    """Agrupa hosts, URLs e nomes de parâmetros a partir de uma linha por ativo."""
    hosts, urls, parameters = set(), set(), set()
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#") or any(char.isspace() for char in value):
            continue
        is_url = "://" in value
        try:
            parsed = urlsplit(value if is_url else "//" + value)
            host = parsed.hostname
        except ValueError:
            continue
        if not host or parsed.username is not None:
            continue
        if is_url:
            if parsed.scheme not in {"http", "https"}:
                continue
            urls.add(parsed._replace(query="", fragment="").geturl())
            parameters.update(unquote_plus(field.partition("=")[0])
                              for field in parsed.query.split("&") if field.partition("=")[0])
        elif parsed.path or parsed.query or parsed.fragment:
            continue
        hosts.add(host.rstrip("."))
    return f"{len(hosts)} hosts únicos · {len(urls)} URLs sem consulta · {len(parameters)} nomes de parâmetros"


def print_catalog(level=None):
    for number, (title, objectives) in enumerate(LEVELS, start=1):
        if level is not None and level != number:
            continue
        print(f"Nível {number} — {title}")
        for objective, tools, guidance in objectives:
            print(f"  {objective}\n    {tools}\n    {guidance}")


TOOL_COMMANDS = {
    "Subfinder": "subfinder -d example.org -silent",
    "assetfinder": "assetfinder --subs-only example.org",
    "dnsx": "dnsx -l hosts.txt -a -resp",
    "waybackurls": "waybackurls < dominios.txt",
    "gau": "gau example.org",
    "waymore": "waymore -i example.org -mode U",
    "gf": "gf -list",
    "Ollama": "ollama list",
    "LinkFinder": "python3 linkfinder.py -i app.js -o cli",
    "ReconAIzer": "Burp Suite › Extensions › ReconAIzer",
    "BurpGPT": "Burp Suite › Extensions › BurpGPT",
    "Burp AI": "Burp Suite › Burp AI",
    "whois": "whois example.org",
    "dig": "dig +short example.org A",
    "curl (crt.sh)": "curl --fail 'https://crt.sh/?q=%25.example.org&output=json'",
    "RDAP": "curl --fail https://rdap.org/domain/example.org",
    "grep": "grep -n 'https://' urls.txt",
}
TOOL_EXECUTABLES = {
    "OWASP Amass": "amass", "Katana": "katana", "Arjun": "arjun",
    "ParamSpider": "paramspider", "Nuclei": "nuclei", "Dalfox": "dalfox",
    "GoWitness": "gowitness", "Interactsh": "interactsh-client",
    "PentestGPT": "pentestgpt", "hackingBuddyGPT": "wintermute",
    "Strix": "strix", "Shannon": "shannon", "Vulnhuntr": "vulnhuntr",
    "Retire.js": "retire", "OWASP ZAP (CLI)": "zaproxy", "OWASP ZAP": "zaproxy",
}


def tool_command(tool):
    if tool in TOOL_COMMANDS:
        return TOOL_COMMANDS[tool]
    executable = TOOL_EXECUTABLES.get(tool, tool.split(" (", 1)[0])
    if executable.endswith(".py"):
        return f"python3 {executable} --help"
    if executable.isascii() and executable.replace(".", "").replace("-", "").isalnum():
        return f"command -v {executable}"
    return "Consultar as evidências da fase no CyberPM."
