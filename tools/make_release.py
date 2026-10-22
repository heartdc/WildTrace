#!/usr/bin/env python3
"""Pack the submitted source tree into one archive.

`git archive` gives a reproducible snapshot of the committed tree -- ignored
files (.venv, .cache, node_modules, local scans) stay out by construction. The
built frontend is the one exception: it is git-ignored but the workbench needs
it, so it is appended when present (`--no-frontend` disables that).

    python tools/make_release.py [--output dist] [--no-frontend]

Prints the archive path, its size, entry count and SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {'node_modules', '__pycache__', '.git'}


def git(*args: str) -> str:
    return subprocess.run(['git', *args], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def build(output_dir: Path, with_frontend: bool) -> Path:
    rev = git('rev-parse', '--short', 'HEAD')
    dirty = bool(git('status', '--porcelain'))
    tag = subprocess.run(['git', 'describe', '--tags', '--always'], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    name = f'WildTrace-{tag or rev}' + ('-dirty' if dirty else '')
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f'{name}.zip'

    subprocess.run(['git', 'archive', '--format=zip', f'--prefix={name}/',
                    '-o', str(archive), 'HEAD'], cwd=ROOT, check=True)

    if with_frontend and (ROOT / 'frontend' / 'dist').is_dir():
        with zipfile.ZipFile(archive, 'a', zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted((ROOT / 'frontend' / 'dist').rglob('*')):
                if path.is_file() and not (set(path.parts) & SKIP_DIRS):
                    target = f'{name}/frontend/dist/{path.relative_to(ROOT / "frontend" / "dist").as_posix()}'
                    bundle.write(path, target)
    return archive


def describe(archive: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    print(f'{archive}')
    print(f'  entries : {len(names)}')
    print(f'  size    : {archive.stat().st_size / 1024 / 1024:.1f} MiB')
    print(f'  sha256  : {digest}')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    parser.add_argument('--no-frontend', action='store_true',
                        help='skip frontend/dist even when it exists')
    args = parser.parse_args(argv)
    if shutil.which('git') is None:
        print('ERROR: git not found', file=sys.stderr)
        return 2
    archive = build(args.output, not args.no_frontend)
    describe(archive)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
