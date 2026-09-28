"""External toolchain resolution and preflight (competition audit 2026-09-23).

The analyzer transports used to hardcode ``/home/airgap/llvm`` (and a
WSL-only bridge). This module centralizes:

* path resolution with explicit environment overrides
  (``OHVUL_LLVM_BIN`` > ``OHVUL_LLVM_ROOT`` > built-in default), so a
  delivery environment can point the tools at its own validated toolchain
  without code changes;
* one bounded ``--version``/existence preflight that exercises the SAME
  command transports the engines use, to be run before demos or batch jobs.

Nothing here executes commands from scan inputs; only fixed probe
arguments are run.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from .review_queue import exclusive_json

DEFAULT_LLVM_ROOT = '/home/airgap/llvm'
DEFAULT_SEMGREP_BIN = '/home/airgap/semgrep-venv/bin/semgrep'

_ENV_BIN = 'OHVUL_LLVM_BIN'
_ENV_ROOT = 'OHVUL_LLVM_ROOT'
_ENV_SEMGREP = 'OHVUL_SEMGREP_BIN'


def wsl_prefix() -> list[str]:
    """Windows hosts bridge through WSL Ubuntu; POSIX hosts run natively."""
    return ['wsl.exe', '-d', 'Ubuntu', '--'] if os.name == 'nt' else []


def resolve_llvm_root() -> str:
    root = os.environ.get(_ENV_ROOT)
    if root is not None:
        if not root.strip():
            raise ValueError(f'{_ENV_ROOT} must be a nonempty LLVM root path when set')
        return root.rstrip('/') or '/'
    return DEFAULT_LLVM_ROOT


def resolve_clang_bin() -> str:
    binary = os.environ.get(_ENV_BIN)
    if binary is not None:
        if not binary.strip():
            raise ValueError(f'{_ENV_BIN} must be a nonempty clang path when set')
        return binary
    return resolve_llvm_root() + '/bin/clang'


def resolve_clang_tidy_bin() -> str:
    binary = os.environ.get(_ENV_BIN)
    if binary is not None:
        # An explicit clang path implies its sibling tidy; keep any Windows
        # executable suffix and never rewrite path separators (WSL posix paths).
        for suffix in ('.exe', '.cmd', '.bat'):
            if binary.lower().endswith(suffix):
                return binary[:-len(suffix)] + '-tidy' + binary[-len(suffix):]
        return binary + '-tidy'
    return resolve_llvm_root() + '/bin/clang-tidy'


def resolve_semgrep_bin() -> str:
    binary = os.environ.get(_ENV_SEMGREP)
    if binary is not None:
        if not binary.strip():
            raise ValueError(f'{_ENV_SEMGREP} must be a nonempty semgrep path when set')
        return binary
    return DEFAULT_SEMGREP_BIN


def _probe(command: list[str], timeout: int) -> dict:
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   encoding='utf-8', errors='replace',
                                   timeout=timeout, shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'unreachable', 'detail': type(exc).__name__}
    detail = (completed.stdout or completed.stderr or '').strip().splitlines()
    return {
        'status': 'ok' if completed.returncode == 0 else 'failed',
        'returncode': completed.returncode,
        'detail': detail[0][:200] if detail else '',
    }


def preflight(timeout: int = 20) -> dict:
    """Exercise the real transports with fixed probes; never runs scan input."""
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise ValueError('preflight timeout must be 1..120 seconds')
    checks = []

    def record(name, required, result):
        checks.append({'name': name, 'required': required, **result})

    if os.name == 'nt':
        record('wsl_bridge', True, _probe(['wsl.exe', '--status'], timeout))
    clang = resolve_clang_bin()
    record('clang', True, _probe(wsl_prefix() + [clang, '--version'], timeout))
    tidy = resolve_clang_tidy_bin()
    record('clang_tidy', True, _probe(wsl_prefix() + [tidy, '--version'], timeout))
    record('semgrep', False, _probe(wsl_prefix() + [resolve_semgrep_bin(), '--version'], timeout))

    failed_required = [c['name'] for c in checks if c['required'] and c['status'] != 'ok']
    return {
        'schema': 'wildtrace-toolchain-preflight-0.1',
        'ok': not failed_required,
        'failed_required': failed_required,
        'resolved': {
            'llvm_root': resolve_llvm_root() if os.environ.get(_ENV_BIN) is None else '(from OHVUL_LLVM_BIN)',
            'clang_bin': clang,
            'clang_tidy_bin': tidy,
            'semgrep_bin': resolve_semgrep_bin(),
            'platform': os.name,
        },
        'checks': checks,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=20)
    args = parser.parse_args(argv)
    result = preflight(timeout=args.timeout)
    exclusive_json(args.output, result)
    print(f"TOOLCHAIN_PREFLIGHT ok={result['ok']} clang={result['resolved']['clang_bin']}")
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
