"""High contrast action colors shared by the classroom tools."""
from tkinter import ttk


def configure_ctf_styles(parent):
    style = ttk.Style(parent)
    for name, background, foreground, active, pressed in [
        ('CtfNav.TButton', '#26364c', '#e2e8f0', '#3a516d', '#1f2e42'),
        ('CtfRun.TButton', '#4ade80', '#06210f', '#86efac', '#30b965'),
        ('CtfExample.TButton', '#facc15', '#261e00', '#fde68a', '#dfb514'),
        ('CtfInfo.TButton', '#60a5fa', '#081d38', '#93c5fd', '#3f8ce6'),
        ('CtfStop.TButton', '#fb7185', '#310c14', '#fda4af', '#e65e76'),
        ('CtfAssistant.TButton', '#26364c', '#fb7185', '#3a516d', '#1f2e42'),
    ]:
        style.configure(name, background=background, foreground=foreground, padding=(9, 6),
                        font=('TkDefaultFont', 9, 'bold'), borderwidth=1, relief='flat')
        colors = [('disabled', '#293b4f'), ('pressed', pressed),
                  ('active', active), ('!disabled', background)]
        style.map(name, background=colors, lightcolor=colors, darkcolor=colors,
                  foreground=[('disabled', '#a9bace'), ('!disabled', foreground)],
                  bordercolor=[('focus', '#ffffff'), ('!focus', background)])
    style.configure('CtfAssistant.TButton', font=('TkDefaultFont', 12, 'bold'),
                    padding=(5, 3), width=3)
