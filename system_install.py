"""Install a missing Kali package through the system authentication dialog."""
import shutil
from tkinter import messagebox


def package_install_command(parent, tool, package):
    """Explain the missing tool and return a pkexec command after confirmation."""
    pkexec = shutil.which('pkexec')
    apt_get = shutil.which('apt-get')
    if not pkexec or not apt_get:
        messagebox.showerror(
            'Ferramenta ausente',
            f'{tool} não está instalado. A instalação automática requer Kali/Debian com '
            'apt-get e pkexec. Instale manualmente com: '
            f'sudo apt install {package}',
            parent=parent)
        return None
    approved = messagebox.askyesno(
        f'Instalar {tool}',
        f'{tool} não está instalado. O Cyberpm vai abrir a autenticação do sistema '
        f'para instalar o pacote {package}. Digite sua senha na janela oficial do Kali.',
        parent=parent)
    if not approved:
        return None
    return [pkexec, apt_get, 'install', '-y', package]
