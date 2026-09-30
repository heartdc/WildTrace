from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os

from .source_scope import is_link


DEFAULT_MAX_FILES = 100_000
DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 200_000
_CHUNK_BYTES = 1024 * 1024


def _tree_files(root: Path, max_files: int, max_entries: int) -> list[Path]:
    pending, files, seen = [root], [], 0
    while pending:
        directory = pending.pop()
        if is_link(directory):
            raise ValueError("source directory changed while snapshotting")
        with os.scandir(directory) as entries:
            for entry in entries:
                seen += 1
                if seen > max_entries:
                    raise ValueError("source snapshot enumeration budget exceeded")
                path = Path(entry.path)
                if is_link(path):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files.append(path)
                    if len(files) > max_files:
                        raise ValueError("source snapshot file budget exceeded")
    return sorted(files)


def _identity(stat):
    # Windows path stat and descriptor stat may expose different ctime semantics.
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def source_snapshot(root: Path, *, max_files=DEFAULT_MAX_FILES,
                    max_bytes=DEFAULT_MAX_BYTES, max_entries=DEFAULT_MAX_ENTRIES) -> str:
    """Hash the whole tree with legacy digest semantics and bounded memory/read work.

    Links are excluded as in the original tree contract. This is a consistency
    check on local inputs, not an operating-system filesystem sandbox.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("snapshot root must be an existing directory")
    if any(type(value) is not int or value < 1 for value in (max_files, max_bytes, max_entries)):
        raise ValueError("snapshot budgets must be positive integers")
    files = _tree_files(root, max_files, max_entries)
    entries = []
    total = 0
    for path in files:
        if is_link(path):
            raise ValueError("source file changed while snapshotting")
        before = path.stat()
        if total + before.st_size > max_bytes:
            raise ValueError("source snapshot byte budget exceeded")
        digest = hashlib.sha256()
        observed = 0
        with path.open("rb") as stream:
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                raise ValueError("source file changed while snapshotting")
            while chunk := stream.read(min(_CHUNK_BYTES, max_bytes - total + 1)):
                observed += len(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("source snapshot byte budget exceeded")
                digest.update(chunk)
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                raise ValueError("source file changed while snapshotting")
        after = path.stat()
        if is_link(path) or observed != before.st_size or _identity(before) != _identity(after):
            raise ValueError("source file changed while snapshotting")
        entries.append({"path": path.relative_to(root).as_posix(),
                        "size": observed, "sha256": digest.hexdigest()})
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()
