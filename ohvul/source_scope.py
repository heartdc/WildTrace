"""Small shared path contract, not an operating-system sandbox."""
from pathlib import Path, PurePosixPath, PureWindowsPath
import os
import re


def relative_path(value: str, *, allow_root: bool = False) -> str:
    if (not isinstance(value, str) or not value or value != value.strip()
            or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid relative input path')
    win = PureWindowsPath(value)
    path = PurePosixPath(value.replace('\\', '/'))
    if win.drive or win.root or path.is_absolute() or ':' in value or '..' in path.parts:
        raise ValueError('input path must stay relative to source root')
    for part in path.parts:
        if part.endswith((' ', '.')) or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', part):
            raise ValueError('ambiguous or reserved input path')
    normalized = path.as_posix()
    if normalized == '.' and not allow_root:
        raise ValueError('input must name a relative file')
    return normalized


def relative_paths(values, *, allow_root=False, nonempty=False) -> list[str]:
    if not isinstance(values, (list, tuple)) or (nonempty and not values):
        raise ValueError('input paths must be an explicit list')
    names = [relative_path(value, allow_root=allow_root) for value in values]
    if len({os.path.normcase(name) for name in names}) != len(names):
        raise ValueError('duplicate or aliased input paths')
    return names


def is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, 'is_junction', lambda: False)()


def local_input_path(root: Path, value: str, *, allow_root=False) -> Path:
    root = Path(root).resolve()
    name = relative_path(value, allow_root=allow_root)
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        if is_link(current):
            raise ValueError('input path contains a symbolic link or junction')
    resolved = current.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError('input path escapes source root')
    return resolved
