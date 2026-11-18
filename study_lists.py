"""Generate and export small datasets for classroom exercises."""
import csv
from io import StringIO
from itertools import cycle, product, zip_longest
from string import ascii_lowercase
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from ctf_theme import configure_ctf_styles
from ctf_tools import save_wordlist


LIMIT = 50_000
MIXED_MODE = 'Misturar dados de teste'
MODES = ('Sequência numérica', 'Alfabeto e combinações curtas', 'Nomes e termos', MIXED_MODE)
DATASET_HEADERS = ('nome', 'clube', 'numero')
PRESETS = {
    'Nomes próprios (exemplos)': ('Ana', 'Bruno', 'Camila', 'Diego', 'Eduarda', 'Felipe', 'Gabriela',
                                  'Henrique', 'Isabela', 'João', 'Luísa', 'Mariana', 'Pedro', 'Rafael', 'Sofia'),
    'Clubes brasileiros (exemplos)': (
        'Athletico Paranaense', 'Atlético Mineiro', 'Bahia', 'Botafogo', 'Ceará', 'Corinthians',
        'Coritiba', 'Cruzeiro', 'Flamengo', 'Fluminense', 'Fortaleza', 'Grêmio', 'Internacional',
        'Palmeiras', 'Remo', 'Santos', 'São Paulo', 'Sport', 'Vasco da Gama', 'Vitória',
    ),
}


def numbers(start, end, width):
    try:
        start, end, width = int(start), int(end), int(width)
    except ValueError:
        raise ValueError('Informe números inteiros nos campos Início, Fim e Largura.') from None
    if not 0 <= start <= end <= 10**12 - 1:
        raise ValueError('Use um intervalo crescente de números entre 0 e 999999999999.')
    if not 0 <= width <= 12:
        raise ValueError('A largura deve estar entre 0 e 12.')
    if end - start + 1 > LIMIT:
        raise ValueError(f'O intervalo pode gerar até {LIMIT} itens por vez.')
    return [str(number).zfill(width) for number in range(start, end + 1)]


def case_options(text, lower, upper):
    return (text,) + ((text.lower(),) if lower else ()) + ((text.upper(),) if upper else ())


def letters(alphabet, length, lower=False, upper=False):
    alphabet = ''.join(dict.fromkeys(alphabet.strip()))
    if not alphabet or not alphabet.isalpha() or len(alphabet) > 36:
        raise ValueError('Informe de 1 a 36 letras, sem espaços ou pontuação.')
    try:
        length = int(length)
    except ValueError:
        raise ValueError('Informe o comprimento como um número inteiro de 1 a 3.') from None
    if length not in (1, 2, 3):
        raise ValueError('O comprimento deve ser 1, 2 ou 3.')
    alphabet = tuple(dict.fromkeys(form for letter in alphabet
                                   for form in case_options(letter, lower, upper)
                                   if len(form) == 1))
    if len(alphabet) ** length > LIMIT:
        raise ValueError(f'Esta configuração passa de {LIMIT} itens. Reduza o alfabeto ou o comprimento.')
    return [''.join(each) for each in product(alphabet, repeat=length)]


def terms(text, lower=False, upper=False):
    if len(text) > 1_000_000:
        raise ValueError('Cole até 1 milhão de caracteres por vez.')
    rows = list(dict.fromkeys(form for line in text.splitlines() if line.strip()
                              for form in case_options(line.strip(), lower, upper)))
    if not rows:
        raise ValueError('Digite um nome ou termo por linha ou escolha um grupo de exemplos.')
    if len(rows) > LIMIT:
        raise ValueError(f'A lista pode ter até {LIMIT} itens por vez.')
    return rows


def interleave_values(names, clubs, sequence):
    text = list(dict.fromkeys(value for group in zip_longest(names, clubs, sequence)
                             for value in group if value is not None))
    if len(text) > LIMIT:
        raise ValueError(f'A lista TXT intercalada excede {LIMIT} itens. Reduza o intervalo ou as listas de entrada.')
    return text


def export_rows(path, rows, format_name, headers=('valor',)):
    if format_name == 'TXT':
        save_wordlist(path, rows)
        return
    stream = StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(headers)
    for row in rows:
        fields = (row,) if isinstance(row, str) else row
        # Preserve spreadsheet safety when users enter their own labels.
        writer.writerow(["'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r', '\n'))
                         else value for value in fields])
    save_wordlist(path, ('\ufeff' + stream.getvalue()).splitlines())


def open_study_lists(parent):
    window = getattr(parent, 'study_lists_window', None)
    if window is None or not window.winfo_exists():
        window = parent.study_lists_window = StudyListsWindow(parent)
    window.lift()
    window.focus_set()


class StudyListsWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        configure_ctf_styles(self)
        self.title('Gerador de listas')
        self.geometry('760x700')
        self.minsize(600, 560)
        self.mode = tk.StringVar(value=MODES[0])
        self.start = tk.StringVar(value='0')
        self.end = tk.StringVar(value='999')
        self.width = tk.StringVar(value='0')
        self.alphabet = tk.StringVar(value=ascii_lowercase)
        self.length = tk.StringVar(value='1')
        self.preset = tk.StringVar()
        self.lower = tk.BooleanVar(value=False)
        self.upper = tk.BooleanVar(value=False)
        self.status = tk.StringVar()
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Escolha o tipo de lista, gere todos os itens do intervalo e exporte o conjunto completo.',
                  wraplength=560).pack(anchor='w', pady=(0, 8))
        chooser = ttk.Combobox(frame, textvariable=self.mode, values=MODES, state='readonly')
        chooser.pack(fill='x')
        chooser.bind('<<ComboboxSelected>>', self.show_panel)
        panel = ttk.Frame(frame)
        panel.pack(fill='x', pady=10)
        self.panels = {mode: ttk.Frame(panel) for mode in MODES}
        numeric = self.panels[MODES[0]]
        for label, value in (('Início', self.start), ('Fim (inclusive)', self.end), ('Largura mínima', self.width)):
            self.field(numeric, label, value)
        ttk.Label(numeric, text='0 a 999 gera 1000 linhas. Largura 8 gera 00000000 até 00000999.').pack(anchor='w')
        alpha = self.panels[MODES[1]]
        self.field(alpha, 'Alfabeto', self.alphabet)
        self.field(alpha, 'Comprimento', self.length)
        ttk.Label(alpha, text='Exemplo com ab e comprimento 2: aa, ab, ba, bb.').pack(anchor='w')
        custom = self.panels[MODES[2]]
        picker = ttk.Combobox(custom, textvariable=self.preset, values=tuple(PRESETS), state='readonly')
        picker.pack(fill='x', pady=(0, 4))
        picker.bind('<<ComboboxSelected>>', self.load_preset)
        ttk.Label(custom, text='Escolha um grupo de exemplos ou escreva um item por linha.').pack(anchor='w')
        self.input = ScrolledText(custom, height=5, wrap='word')
        self.input.pack(fill='x')
        mixed = self.panels[MIXED_MODE]
        ttk.Label(mixed, text='CSV: um número por linha, com nome e clube em colunas. '
                  'TXT: itens das três fontes intercalados, um por linha.',
                  wraplength=560).pack(anchor='w', pady=(0, 5))
        columns = ttk.Frame(mixed)
        columns.pack(fill='x')
        self.names_input = self.dataset_field(columns, 'Nomes', PRESETS['Nomes próprios (exemplos)'])
        self.clubs_input = self.dataset_field(columns, 'Clubes', PRESETS['Clubes brasileiros (exemplos)'])
        self.case_controls = ttk.Frame(frame)
        ttk.Checkbutton(self.case_controls, text='Incluir minúsculas', variable=self.lower).pack(side='left')
        ttk.Checkbutton(self.case_controls, text='Incluir MAIÚSCULAS', variable=self.upper).pack(side='left', padx=8)
        controls = ttk.Frame(frame)
        controls.pack(fill='x', pady=(0, 8))
        self.actions = controls
        ttk.Button(controls, text='Gerar lista completa', style='CtfRun.TButton', command=self.generate).pack(side='left')
        for format_name in ('TXT', 'CSV'):
            ttk.Button(controls, text='Exportar '+format_name,
                       command=lambda fmt=format_name: self.generate(fmt)).pack(side='left', padx=6)
        ttk.Label(frame, textvariable=self.status, wraplength=560).pack(anchor='w', pady=(0, 6))
        self.output = ScrolledText(frame, height=12, wrap='none', state='disabled')
        self.output.pack(fill='both', expand=True)
        self.show_panel()

    def field(self, parent, label, value):
        row = ttk.Frame(parent)
        row.pack(fill='x', pady=(0, 4))
        ttk.Label(row, text=label, width=19).pack(side='left')
        ttk.Entry(row, textvariable=value).pack(side='left', fill='x', expand=True)

    def dataset_field(self, parent, label, examples):
        column = ttk.Frame(parent)
        column.pack(side='left', fill='x', expand=True, padx=(0, 8))
        ttk.Label(column, text=label + ' · um por linha').pack(anchor='w')
        field = ScrolledText(column, height=4, width=26, wrap='word')
        field.pack(fill='x')
        field.insert('1.0', '\n'.join(examples))
        return field

    def show_panel(self, event=None):
        for panel in self.panels.values():
            panel.pack_forget()
        mode = self.mode.get()
        if mode == MIXED_MODE:
            self.panels[MODES[0]].pack(fill='x', pady=(0, 8))
        self.panels[mode].pack(fill='x')
        self.case_controls.pack_forget()
        if mode != MODES[0]:
            self.case_controls.pack(fill='x', before=self.actions, pady=(0, 8))
        self.show_output('')
        self.status.set(f'A janela e o arquivo exibem a lista completa, com até {LIMIT} itens por geração.')

    def show_output(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', text)
        self.output.configure(state='disabled')

    def load_preset(self, event=None):
        self.input.delete('1.0', 'end')
        self.input.insert('1.0', '\n'.join(PRESETS[self.preset.get()]))

    def generate(self, format_name=None):
        try:
            mode = self.mode.get()
            headers = ('valor',)
            if mode == MODES[0]:
                rows = numbers(self.start.get(), self.end.get(), self.width.get())
            elif mode == MODES[1]:
                rows = letters(self.alphabet.get(), self.length.get(), self.lower.get(), self.upper.get())
            elif mode == MIXED_MODE:
                lower, upper = self.lower.get(), self.upper.get()
                names = terms(self.names_input.get('1.0', 'end-1c'), lower, upper)
                clubs = terms(self.clubs_input.get('1.0', 'end-1c'), lower, upper)
                sequence = numbers(self.start.get(), self.end.get(), self.width.get())
                if format_name == 'TXT':
                    rows = interleave_values(names, clubs, sequence)
                else:
                    rows = list(zip(cycle(names), cycle(clubs), sequence))
                    headers = DATASET_HEADERS
            else:
                rows = terms(self.input.get('1.0', 'end-1c'), self.lower.get(), self.upper.get())
            if headers == DATASET_HEADERS:
                self.show_output('\n'.join('\t'.join(row) for row in [headers, *rows]))
            else:
                self.show_output('\n'.join(rows))
            self.status.set(f'{len(rows)} itens na lista completa.')
            if format_name:
                extension = '.' + format_name.lower()
                path = filedialog.asksaveasfilename(parent=self, defaultextension=extension,
                                                     filetypes=[(format_name, '*'+extension)])
                if path:
                    export_rows(path, rows, format_name, headers)
                    self.status.set(f'{len(rows)} itens exportados para {path}')
        except (OSError, ValueError) as exc:
            messagebox.showerror('Gerador de listas', str(exc), parent=self)
