"""Capture missing repository pins from explicit local profile inputs.

Existing pins are constraints, not suggestions: they are never refreshed to a
different HEAD. No checkout, install, analyzer, network or target execution.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

from .engine_profile import (
    _decode_profile, _git, _read_profile, _prepare_profile_bytes,
    validate_profile, validate_profile_sources, validate_profile_provenance,
)
from .source_scope import is_link, local_input_path


def _output_path(path: Path, root: Path, template: Path) -> Path:
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if is_link(part):
            raise ValueError('profile output must not contain a symbolic link or junction')
    resolved = path.resolve()
    if resolved.is_relative_to(root):
        raise ValueError('profile output must be outside source root')
    if resolved == template.resolve() or path.exists():
        raise FileExistsError('profile output exists or would overwrite the template')
    if not path.parent.is_dir():
        raise ValueError('profile output parent must already exist')
    return path


def capture_profile(template_path: Path, source_root: Path, output_path: Path) -> dict:
    """Create one fully validated new profile; return an observation receipt.

Only repository owners of explicitly declared sources/include directories are
discovered. Existing repository pins are preserved, including unused pins.
The returned receipt is evidence of local validation, not platform verification.
"""
    root = Path(source_root).resolve()
    template_path = Path(template_path)
    if not root.is_dir():
        raise ValueError('source root must be an existing directory')
    output = _output_path(output_path, root, template_path)
    original = _read_profile(template_path)
    candidate = copy.deepcopy(_decode_profile(original))
    inputs = validate_profile_sources(candidate, root)
    if not inputs['complete']:
        raise ValueError('profile capture requires all declared local inputs')
    added = {}
    for name in candidate['source_files'] + candidate['include_dirs']:
        path = local_input_path(root, name, allow_root=True)
        owner = Path(_git(path if path.is_dir() else path.parent,
                          'rev-parse', '--show-toplevel').strip()).resolve()
        if not owner.is_relative_to(root):
            raise ValueError('input repository owner is outside source root: ' + name)
        relative = owner.relative_to(root).as_posix()
        local_input_path(root, relative, allow_root=True)
        if os.path.normcase(relative) not in {os.path.normcase(x) for x in candidate['source_repositories']}:
            commit = _git(owner, 'rev-parse', '--verify', 'HEAD^{commit}').strip().lower()
            candidate['source_repositories'][relative] = commit
            added[relative] = commit
    candidate['source_repositories'] = dict(sorted(candidate['source_repositories'].items()))
    candidate['status'] = 'local-inputs-captured-not-platform-verified'
    candidate['disclaimer'] = ('Local profile capture only. Existing pins preserved. '
                               'No analyzer or target executed; not a vulnerability verdict.')
    candidate['semgrep_rule_sha256'] = {
        name: hashlib.sha256(local_input_path(root, name).read_bytes()).hexdigest()
        for name in candidate['semgrep_rule_files']
    }
    # An existing rule pin is also a constraint. Do not silently bless new rules.
    expected_rules = _decode_profile(original).get('semgrep_rule_sha256', {})
    if any(candidate['semgrep_rule_sha256'][name] != expected.lower()
           for name, expected in expected_rules.items()):
        raise ValueError('existing template rule digest mismatch')
    candidate = validate_profile(candidate)
    payload = (json.dumps(candidate, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    # Validate the same prepared bytes without publishing a premature candidate.
    _, receipt = _prepare_profile_bytes(payload, root)
    if _read_profile(template_path) != original:
        raise ValueError('template changed during profile capture')
    current = validate_profile_provenance(candidate, root)
    if not current['verified'] or current != receipt['provenance']:
        raise ValueError('repository changed during profile capture')
    if _output_path(output, root, template_path) != output:
        raise ValueError('profile output changed during capture')
    # Exclusive create: a concurrently created destination is never replaced.
    # A failed write can leave an incomplete new file, which is not an accepted
    # profile. No rollback removes paths that might have changed ownership.
    with output.open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return {'schema': 'profile-capture-0.1', 'status': 'captured',
            'template_sha256': hashlib.sha256(original).hexdigest(),
            'profile_sha256': hashlib.sha256(payload).hexdigest(),
            'output': str(output), 'added_repositories': added,
            'validation': receipt, 'analyzers_run': False, 'target_executed': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = capture_profile(args.template, args.source_root, args.output)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
