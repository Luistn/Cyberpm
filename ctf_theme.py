"""High contrast action colors shared by the classroom tools."""
from tkinter import ttk


def configure_ctf_styles(parent):
    style = ttk.Style(parent)
    for name, background, foreground, active in [
        ('CtfRun.TButton', '#4ade80', '#06210f', '#86efac'),
        ('CtfExample.TButton', '#facc15', '#261e00', '#fde68a'),
        ('CtfInfo.TButton', '#60a5fa', '#081d38', '#93c5fd'),
        ('CtfStop.TButton', '#fb7185', '#310c14', '#fda4af'),
    ]:
        style.configure(name, background=background, foreground=foreground, padding=(9, 6),
                        font=('TkDefaultFont', 9, 'bold'), borderwidth=1)
        style.map(name, background=[('disabled', '#293b4f'), ('pressed', active),
                                    ('active', active), ('!disabled', background)],
                  foreground=[('disabled', '#a9bace'), ('!disabled', foreground)],
                  bordercolor=[('focus', '#ffffff'), ('!focus', background)])
