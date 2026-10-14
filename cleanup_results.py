"""Validate the sole directory eligible for local audit-result deletion."""
from pathlib import Path


def result_directory(root, candidate):
    root = Path(root)
    candidate = Path(candidate)
    if root.is_symlink() or candidate.is_symlink():
        raise ValueError('Links simbólicos não podem ser limpos por este botão.')
    allowed = root.resolve()
    selected = candidate.resolve()
    if selected == allowed or selected.parent != allowed or not selected.is_dir():
        raise ValueError('Selecione uma pasta de site dentro de pentest-out. A pasta principal não pode ser apagada.')
    return selected
