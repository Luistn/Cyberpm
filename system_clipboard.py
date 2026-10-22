"""Real OS clipboard, with a Win32 backend for Windows/Tk clipboard crashes."""
import sys
import time


def _win32():
    import ctypes
    from ctypes import wintypes
    user = ctypes.WinDLL('user32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    for name, args, result in (
        ('OpenClipboard', [wintypes.HWND], wintypes.BOOL),
        ('CloseClipboard', [], wintypes.BOOL),
        ('EmptyClipboard', [], wintypes.BOOL),
        ('SetClipboardData', [wintypes.UINT, wintypes.HANDLE], wintypes.HANDLE),
        ('GetClipboardData', [wintypes.UINT], wintypes.HANDLE),
    ):
        function = getattr(user, name)
        function.argtypes, function.restype = args, result
    for name, args, result in (
        ('GlobalAlloc', [wintypes.UINT, ctypes.c_size_t], wintypes.HANDLE),
        ('GlobalLock', [wintypes.HANDLE], ctypes.c_void_p),
        ('GlobalUnlock', [wintypes.HANDLE], wintypes.BOOL),
        ('GlobalFree', [wintypes.HANDLE], wintypes.HANDLE),
    ):
        function = getattr(kernel, name)
        function.argtypes, function.restype = args, result
    return ctypes, user, kernel


def _open(ctypes, user, owner):
    for _ in range(10):
        if user.OpenClipboard(owner):
            return
        time.sleep(0.02)
    raise ctypes.WinError(ctypes.get_last_error())


def write_text(widget, text):
    if sys.platform != 'win32':
        widget.clipboard_clear()
        widget.clipboard_append(text)
        widget.update_idletasks()
        return
    ctypes, user, kernel = _win32()
    data = str(text).encode('utf-16-le') + b'\0\0'
    memory = kernel.GlobalAlloc(0x0002, len(data))
    if not memory:
        raise ctypes.WinError(ctypes.get_last_error())
    opened = False
    try:
        pointer = kernel.GlobalLock(memory)
        if not pointer:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            ctypes.memmove(pointer, data, len(data))
        finally:
            kernel.GlobalUnlock(memory)
        _open(ctypes, user, int(widget.winfo_id()))
        opened = True
        if not user.EmptyClipboard() or not user.SetClipboardData(13, memory):
            raise ctypes.WinError(ctypes.get_last_error())
        memory = None  # The OS now owns the memory.
    finally:
        if opened:
            user.CloseClipboard()
        if memory:
            kernel.GlobalFree(memory)


def read_text(widget):
    if sys.platform != 'win32':
        return widget.clipboard_get()
    ctypes, user, kernel = _win32()
    _open(ctypes, user, None)
    try:
        memory = user.GetClipboardData(13)
        if not memory:
            return ''
        pointer = kernel.GlobalLock(memory)
        if not pointer:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(pointer)
        finally:
            kernel.GlobalUnlock(memory)
    finally:
        user.CloseClipboard()
