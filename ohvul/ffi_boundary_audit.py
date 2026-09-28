"""Find indexed members sharing names with raw FFI array fields.

This is a bounded lexical audit, not a C++ parser or proof of caller reachability.
Every result is a candidate-only review task and retains the source hash.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat

from .review_queue import checked_path, exclusive_json
from .source_scope import relative_paths, local_input_path, is_link
from .detect.lexical import mask_noncode

EXTENSIONS = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}
MAX_FILE_BYTES = 8 * 1024 * 1024
STRUCT_RE = re.compile(r'\bstruct\s+(?P<name>[A-Za-z_]\w*)\s*\{(?P<body>.*?)\}\s*;', re.S)
PTR_FIELD_RE = re.compile(r'\b(?:[A-Za-z_]\w*(?:::\w+)*|[A-Za-z_]\w*\s*<[^;{}>]+>)\s*\*+\s*(?P<name>[A-Za-z_]\w*)\s*;')
SIZE_FIELD_RE = re.compile(r'\b(?:u?int\d+_t|size_t|ssize_t|int|long(?:\s+long)?)\s+(?P<name>size|len|length|count|num)\s*;')
INDEX_RE = re.compile(r'(?P<object>[A-Za-z_]\w*)\s*(?:\.|->)\s*(?P<field>[A-Za-z_]\w*)\s*\[\s*(?P<index>[A-Za-z_]\w*|\d+)\s*\]')
GUARD_WORDS = re.compile(r'\b(?:nullptr|NULL|MAX_[A-Z0-9_]+|size\s*[<>]=?|len\s*[<>]=?|count\s*[<>]=?)\b')


def _line(text: str, offset: int) -> int:
    return text.count('\n', 0, offset) + 1


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.strip().encode('utf-8')).hexdigest()[:16]


def _struct_shapes(text: str):
    shapes = {}
    for match in STRUCT_RE.finditer(text):
        body = match.group('body')
        pointers = [m.group('name') for m in PTR_FIELD_RE.finditer(body)]
        sizes = [m.group('name') for m in SIZE_FIELD_RE.finditer(body)]
        if pointers and sizes:
            for pointer in pointers:
                shapes.setdefault(pointer, []).append(
                    {'struct': match.group('name'), 'size_fields': sizes})
    return shapes


def audit_source(root, relative_files=None):
    root = checked_path(root)
    if not root.is_dir():
        raise ValueError('source root must be a directory')
    findings, errors, records, skipped_dirs = [], [], [], []
    attempted = failed = skipped = 0
    explicit = relative_files is not None
    if explicit:
        names = sorted(relative_paths(relative_files, nonempty=True))
        if any(Path(name).suffix.lower() not in EXTENSIONS for name in names):
            raise ValueError('explicit source must have a supported C/C++ extension')
        # Validate the whole declared scope before reading any source bytes.
        for relative in names:
            checked_path(local_input_path(root, relative))
    else:
        names = []

        def enumeration_error(exc):
            errors.append({'stage': 'enumeration', 'status': 'input_error',
                           'source_file': str(exc.filename or root),
                           'error_type': type(exc).__name__, 'reason': str(exc)[:512]})

        for directory, dirs, files in os.walk(root, followlinks=False, onerror=enumeration_error):
            retained = []
            for name in sorted(dirs):
                path = Path(directory) / name
                if is_link(path) or name.casefold() == '.git':
                    skipped_dirs.append(path.relative_to(root).as_posix())
                else:
                    retained.append(name)
            dirs[:] = retained
            names.extend((Path(directory) / name).relative_to(root).as_posix()
                         for name in files if Path(name).suffix.lower() in EXTENSIONS)
        names.sort()
    documents = []
    for relative in names:
        record = {'file': relative}
        try:
            if not explicit and is_link(root / relative):
                skipped += 1
                records.append({**record, 'status': 'skipped', 'reason': 'symbolic link or junction'})
                continue
            path = checked_path(local_input_path(root, relative))
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError('source input is not a regular file')
            attempted += 1
            with path.open('rb') as stream:
                raw = stream.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise ValueError('file exceeds byte limit')
            text = raw.decode('utf-8')
        except (OSError, UnicodeError, ValueError) as exc:
            failed += 1
            error = {**record, 'status': 'input_error', 'error_type': type(exc).__name__,
                     'reason': str(exc)[:512]}
            errors.append(error)
            records.append(error)
            continue
        digest = hashlib.sha256(raw).hexdigest()
        masked, _ = mask_noncode(text)
        documents.append((relative, text, masked, digest))
        records.append({**record, 'status': 'completed', 'file_sha256': digest, 'bytes': len(raw)})

    # FFI declarations and their conversion functions commonly live in
    # different headers/source files. Build a bounded cross-file shape index.
    shapes = {}
    for _, _, masked, _ in documents:
        for pointer, entries in _struct_shapes(masked).items():
            shapes.setdefault(pointer, []).extend(entries)
    for relative, text, masked, digest in documents:
        lines = text.splitlines()
        seen = set()
        for indexed in INDEX_RE.finditer(masked):
            if not indexed.group('object'):
                continue
            pointer = indexed.group('field')
            if pointer not in shapes:
                continue
            line_no = _line(text, indexed.start())
            key = (relative, line_no, pointer)
            if key in seen:
                continue
            seen.add(key)
            code = lines[line_no - 1].strip() if line_no <= len(lines) else ''
            start = max(0, indexed.start() - 600)
            context = masked[start:indexed.start()]
            guard = bool(GUARD_WORDS.search(context))
            item = {'structs': sorted({shape['struct'] for shape in shapes[pointer]}),
                    'pointer_field': pointer, 'size_fields': sorted({name for shape in shapes[pointer]
                                                                       for name in shape['size_fields']}),
                    'line': line_no, 'object': indexed.group('object'),
                    'code': code, 'guard_hint': guard, 'context_window_bytes': len(context)}
            findings.append({
                'alert_id': f"FFI-{len(findings) + 1:06d}",
                'source': 'ffi-boundary-audit', 'rule': 'raw-array-index-with-size-field',
                'cwe_candidate': 'unknown',
                'description': 'Indexed member shares a name with a pointer field in a size-bearing struct; type association, access direction, bounds and nullability remain unproven.',
                'location': {'file': relative, 'line': item['line']},
                'evidence': {'code': item['code'], 'line_hash': _line_hash(lines[item['line'] - 1]),
                             'file_sha256': digest, 'structs': item['structs'],
                             'object': item['object'], 'pointer_field': item['pointer_field'],
                             'size_fields': item['size_fields'], 'guard_hint': item['guard_hint'],
                             'association': 'field_name_only', 'type_binding': 'unknown',
                             'access_direction': 'unknown', 'bounds': 'unknown', 'nullability': 'unknown',
                             'final_verdict': 'undetermined'},
                'status': 'candidate'
            })
    scope_complete = not any(error.get('stage') == 'enumeration' for error in errors)
    return {'schema': 'ffi-boundary-audit-0.1', 'source_root': str(root),
            'status': 'completed' if not errors else ('partial' if documents else 'input_error'),
            'files_requested': len(names) if scope_complete else None, 'files_discovered': len(names),
            'files_attempted': attempted, 'files_scanned': len(documents),
            'files_failed': failed, 'files_skipped': skipped,
            'scope_complete': scope_complete, 'directories_skipped': skipped_dirs,
            'file_results': records,
            'findings': findings, 'input_errors': errors,
            'candidate_only': True, 'confirmed_vulnerabilities': 0,
            'target_executed': False, 'no_network': True, 'model_invoked': False,
            'limitations': ['Lexical structure matching is not a C++ type or call graph.',
                            'Same-name members are navigation hints, including legal accesses and unrelated object types.',
                            'CWE remains unknown without nullability, bounds and read/write evidence.',
                            'guard_hint is contextual evidence, not proof of validation.',
                            'Caller reachability, ownership and process boundaries require manual review.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit_source(args.source_root)
        exclusive_json(args.output, result, input_paths=[checked_path(args.source_root)])
        print(f"FFI_BOUNDARY candidates={len(result['findings'])} files={result['files_scanned']}")
        return 0 if result['status'] == 'completed' else 1
    except (OSError, ValueError, TypeError) as exc:
        print('FFI_BOUNDARY_REJECTED: ' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
