"""Bounded source snapshot digests for scan integrity checks.

Legacy whole-tree mode (files=None) is preserved for checkpoint binding
callers (cli, component_batch, compiler_analysis) and stays payload-
compatible with previously recorded digests, but is now bounded: streaming
hashes and explicit file/byte/time budgets instead of an unbounded walk.

Scoped mode (files=[...]) is used by the engine shard path: only declared
inputs are validated and hashed, so a missing input is reported without
touching unrelated trees (competition audit 2026-09-23, P1-1).
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import os
import time

DEFAULT_MAX_FILES = 200_000
DEFAULT_MAX_BYTES = 16 * 1024 ** 3
DEFAULT_MAX_SECONDS = 300.0
_CHUNK = 1024 * 1024


def _hash_file(path):
    hasher = hashlib.sha256()
    size = 0
    with path.open('rb') as handle:
        while True:
            block = handle.read(_CHUNK)
            if not block:
                break
            hasher.update(block)
            size += len(block)
    return size, hasher.hexdigest()


def _digest(entries):
    payload = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(payload).hexdigest()


def _check_limits(max_files, max_bytes, max_seconds):
    if type(max_files) is not int or max_files < 1:
        raise ValueError("max_files must be a positive integer")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(max_seconds, (int, float)) or isinstance(max_seconds, bool) or max_seconds < 0:
        raise ValueError("max_seconds must be a non-negative number")


def source_snapshot(root, *, files=None, max_files=DEFAULT_MAX_FILES,
                    max_bytes=DEFAULT_MAX_BYTES, max_seconds=DEFAULT_MAX_SECONDS):
    _check_limits(max_files, max_bytes, max_seconds)
    root = Path(root).resolve()
    started = time.monotonic()

    if files is None:
        entries = []
        total_bytes = 0
        for path in sorted(root.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            if len(entries) >= max_files:
                raise ValueError(f"source snapshot exceeds max_files budget ({max_files})")
            if time.monotonic() - started > max_seconds:
                raise ValueError(f"source snapshot exceeds max_seconds budget ({max_seconds})")
            size, digest = _hash_file(path)
            total_bytes += size
            if total_bytes > max_bytes:
                raise ValueError(f"source snapshot exceeds max_bytes budget ({max_bytes})")
            entries.append({'path': path.relative_to(root).as_posix(), 'size': size, 'sha256': digest})
        return _digest(entries)

    if not isinstance(files, list) or any(not isinstance(x, str) or not x.strip() for x in files):
        raise ValueError("snapshot files must be a list of nonempty relative paths")
    resolved = []
    seen = set()
    for raw in files:
        rel = Path(raw)
        source = (root / rel).resolve()
        if (rel.is_absolute() or rel.drive or '..' in rel.parts or (root / rel).is_symlink()
                or not source.is_relative_to(root) or not source.is_file()):
            raise ValueError(f"snapshot file is not an existing relative file in root: {raw}")
        key = os.path.normcase(str(source))
        if key not in seen:
            seen.add(key)
            resolved.append(source)
    if len(resolved) > max_files:
        raise ValueError(f"source snapshot exceeds max_files budget ({max_files})")
    entries = []
    total_bytes = 0
    for source in sorted(resolved, key=lambda p: p.relative_to(root).as_posix()):
        if time.monotonic() - started > max_seconds:
            raise ValueError(f"source snapshot exceeds max_seconds budget ({max_seconds})")
        size, digest = _hash_file(source)
        total_bytes += size
        if total_bytes > max_bytes:
            raise ValueError(f"source snapshot exceeds max_bytes budget ({max_bytes})")
        entries.append({'path': source.relative_to(root).as_posix(), 'size': size, 'sha256': digest})
    return _digest(entries)
