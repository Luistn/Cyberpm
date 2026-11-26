"""Shared presentation for the CyberPM terminals and tool output."""
import re

from gui_helpers import log_tag


ANSI_STYLE = re.compile(r'\x1b\[[0-9;:]*m')
COLORS = {
    'normal': '#e6edf3',
    'info': '#58a6ff',
    'phase': '#a371f7',
    'success': '#3fb950',
    'warning': '#d29922',
    'error': '#f85149',
    'critical': '#ff7b72',
    'finding': '#db61a2',
}


def configure_terminal(widget):
    widget.configure(background='#000000', foreground=COLORS['normal'],
                     insertbackground=COLORS['info'], selectbackground='#334866',
                     selectforeground='#ffffff', font=('TkFixedFont', 10),
                     relief='flat', padx=8, pady=6)
    for tag, color in COLORS.items():
        widget.tag_configure(tag, foreground=color)
    widget.tag_configure('command', foreground='#79e6d2', background='#122a30',
                         font=('TkFixedFont', 10, 'bold'))
    widget.tag_configure('result', foreground='#b9f6ca', background='#123524',
                         font=('TkFixedFont', 11, 'bold'))


def terminal_tag(line):
    start = line.lstrip().casefold()
    if start.startswith('[+]'):
        return 'result'
    if start.startswith(('[error]', 'erro:', 'error:', 'não foi possível')):
        return 'error'
    if start.startswith(('[-]', '[warning]', 'warning:', 'aviso:')):
        return 'warning'
    if start.startswith(('(*)', '[*]')):
        return 'info'
    if start.startswith(('(gdb)', '$ ')):
        return 'command'
    return log_tag(line)


def insert_terminal(widget, text, tag=None):
    for line in ANSI_STYLE.sub('', text).splitlines(keepends=True):
        widget.insert('end', line, tag or terminal_tag(line))
