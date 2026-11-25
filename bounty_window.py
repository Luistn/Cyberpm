"""Menu de objetivos Bug Bounty."""
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from bounty_catalog import LEVELS, TOOL_DESCRIPTIONS, summarize_inventory, tool_command


class BountyWindow(tk.Toplevel):
    def __init__(self, parent, phases=()):
        super().__init__(parent)
        self.title("CyberPM — Guia de ferramentas")
        self.geometry("920x540")
        self.minsize(660, 440)

        content = ttk.Frame(self, padding=12)
        content.pack(fill="both", expand=True)
        panes = ttk.Panedwindow(content, orient="horizontal")
        panes.pack(fill="both", expand=True)
        menu = ttk.Frame(panes)
        details = ttk.Frame(panes, padding=(16, 8))
        panes.add(menu, weight=3)
        panes.add(details, weight=2)

        tree = ttk.Treeview(menu, show="tree", selectmode="browse")
        scrollbar = ttk.Scrollbar(menu, orient="vertical", command=tree.yview)
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(fill="both", expand=True)

        entries = {}
        for number, (title, objectives) in enumerate(LEVELS, start=1):
            level = tree.insert("", "end", text=f"Nível {number} — {title}", open=number == 1)
            entries[level] = (title, "", "Selecione um objetivo deste nível para ver as ferramentas.")
            for objective, tools, guidance in objectives:
                item = tree.insert(level, "end", text=objective)
                descriptions = "\n\n".join(
                    f"{tool} — {TOOL_DESCRIPTIONS[tool]}\n{tool_command(tool)}"
                    for tool in tools.split(" · ")
                )
                entries[item] = (objective, tools, f"{descriptions}\n\n{guidance}")

        phase_group = tree.insert("", "end", text="Ferramentas por fase")
        entries[phase_group] = ("Ferramentas por fase", "", "Selecione uma fase para ver suas ferramentas.")
        for number, name, tools in phases:
            caption = f"Fase {number:02d} — {name}"
            item = tree.insert(phase_group, "end", text=caption)
            commands = "\n\n".join(
                f"{tool}\n{tool_command(tool)}" for tool in tools.split(", ")
            )
            entries[item] = (caption, "", commands)

        heading = ttk.Label(details, font=("TkDefaultFont", 12, "bold"), wraplength=270)
        heading.pack(anchor="w", fill="x", pady=(0, 12))
        body = scrolledtext.ScrolledText(details, wrap="word", bg="#161b22", fg="#ffffff",
                                        font=("Monospace", 10), width=30, padx=10, pady=10)
        body.pack(fill="both", expand=True)
        body.configure(state="disabled")

        def show_selection(_event=None):
            selection = tree.selection()
            if selection:
                title, _, description = entries[selection[0]]
                heading.configure(text=title)
                body.configure(state="normal")
                body.delete("1.0", "end")
                body.insert("1.0", description)
                body.configure(state="disabled")

        tree.bind("<<TreeviewSelect>>", show_selection)
        first = tree.get_children(tree.get_children()[0])[0]
        tree.selection_set(first)
        tree.focus(first)
        show_selection()

        actions = ttk.Frame(content)
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="Inventariar lista local…", command=self.inventory).pack(side="left")

    def inventory(self):
        path = filedialog.askopenfilename(
            parent=self, title="Selecione uma lista com um host ou URL por linha",
            filetypes=[("Listas de texto", "*.txt"), ("Todos os arquivos", "*")],
        )
        if path:
            try:
                with open(path, encoding="utf-8-sig") as source:
                    summary = summarize_inventory(source)
            except (OSError, UnicodeError) as error:
                messagebox.showerror("Inventário local", str(error), parent=self)
                return
            messagebox.showinfo("Inventário local", summary, parent=self)
