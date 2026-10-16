#!/usr/bin/env python3
"""Repair selected duplicate Ninja edges; always probe the actual target.

Derived from AerGap's local .cache/sweep_v3.py. Default mode never writes.
Only generated .ninja files beneath --output may be changed.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def rules(output, target):
    found = []
    for base, dirs, names in os.walk(output):
        dirs[:] = sorted(d for d in dirs if not (Path(base) / d).is_symlink())
        for name in sorted(names):
            path = Path(base) / name
            if path.suffix != '.ninja' or path.is_symlink():
                continue
            text = path.read_bytes().decode('utf-8')
            lines = text.splitlines(keepends=True)
            for start, line in enumerate(lines):
                if not line.startswith(f'build {target}:'):
                    continue
                end = start + 1
                while end < len(lines) and (lines[end].startswith((' ', '\t')) or not lines[end].strip()):
                    end += 1
                # Do not partially rewrite multiline Ninja edges.
                block = ''.join(lines[start:end])
                if any(x.rstrip().endswith('$') for x in lines[start:end]):
                    raise ValueError('Unsupported continued edge: ' + str(path))
                found.append((path, start, end, block))
    return found


def choose(hits, target, output, preferred):
    if len(hits) < 2:
        raise ValueError('RULES_NOT_FOUND: ' + target)
    for hit in hits:
        lines = hit[3].splitlines()
        if re.fullmatch(rf'build {re.escape(target)}: (?:clang_x64_)?stamp {re.escape(target)}\s*', lines[0]) and all(not x.strip() for x in lines[1:]):
            return hit, 'self-stamp'
    # Compare the entire edge including variables, not just its first line.
    if len({h[3].strip() for h in hits}) == 1:
        return hits[-1], 'identical-edge'
    keep = [h for h in hits if h[0].relative_to(output).as_posix() in preferred]
    other = [h for h in hits if h not in keep]
    if len(keep) == 1 and other:
        return other[-1], 'explicit-preferred-file'
    raise ValueError('UNHANDLED: differing edges for ' + target + '; inspect bindings before --prefer-file')


def sweep(output, ninja, target, apply=False, backup=None, preferred=(), max_iterations=4000, timeout=30):
    output = Path(output).resolve(strict=True)
    ninja = Path(ninja).resolve(strict=True)
    if not output.is_dir() or not (output / 'build.ninja').is_file():
        raise ValueError('Output must contain build.ninja')
    if not target or target.startswith('-') or '\n' in target:
        raise ValueError('A literal non-option Ninja target is required')
    for name in preferred:
        p = Path(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name:
            raise ValueError('--prefer-file requires an output-relative POSIX path')
    if apply:
        if backup is None:
            raise ValueError('--apply requires --backup-dir')
        backup = Path(backup).resolve()
        if backup.is_relative_to(output) or backup.exists():
            raise ValueError('Backup must be a new directory outside output')
    edits = 0
    for iteration in range(max_iterations + 1):
        probe = subprocess.run([str(ninja), '-C', str(output), '-n', target],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               text=True, encoding='utf-8', errors='replace', timeout=timeout)
        if probe.returncode == 0:
            print(f'GRAPH_CLEAN edits={edits} target={target}')
            return 0
        match = re.search(r'ninja: error: .*?:\d+: multiple rules generate (\S+)', probe.stderr)
        if not match:
            print('OTHER_PROBE: ' + probe.stderr.strip(), file=sys.stderr)
            return 1
        duplicate = match.group(1)
        hit, reason = choose(rules(output, duplicate), duplicate, output, preferred)
        path, start, end, block = hit
        rel = path.relative_to(output)
        print(f'{"EDIT" if apply else "CHECK"} {reason} {rel.as_posix()}:{start + 1} target={duplicate}', flush=True)
        if not apply:
            return 2
        if iteration == max_iterations:
            raise ValueError('Iteration limit reached; graph remains incomplete')
        raw = path.read_bytes()
        lines = raw.decode('utf-8').splitlines(keepends=True)
        if ''.join(lines[start:end]) != block:
            raise ValueError('Ninja file changed during probe')
        if not backup.exists():
            backup.mkdir(parents=True, exist_ok=False)
        saved = backup / rel
        if not saved.exists():
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, saved)
        updated = ''.join(lines[:start] + lines[end:]).encode('utf-8')
        # Keep a per-file backup plus append-only hashes of each edit.
        path.write_bytes(updated)
        with (backup / 'edits.tsv').open('a', encoding='utf-8') as log:
            log.write(f'{rel.as_posix()}\t{hashlib.sha256(raw).hexdigest()}\t{hashlib.sha256(updated).hexdigest()}\t{reason}\n')
        edits += 1
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--ninja', type=Path, help='Default: SOURCE/prebuilts/build-tools/linux-x86/bin/ninja')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-dir', type=Path)
    parser.add_argument('--prefer-file', action='append', default=[], help='Explicitly keep the sole edge from this output-relative file')
    parser.add_argument('--max-iterations', type=int, default=4000)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args(argv)
    try:
        if args.max_iterations < 1 or args.timeout < 1:
            raise ValueError('Limits must be positive')
        return sweep(args.output, args.ninja or args.source_root / 'prebuilts/build-tools/linux-x86/bin/ninja',
                     args.target, args.apply, args.backup_dir, args.prefer_file, args.max_iterations, args.timeout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print('SWEEP_FAILED: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
