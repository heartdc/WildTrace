"""Real-library verification for drafts that load an OpenHarmony `.so`.

The Windows guarded heap only works for targets compiled from source; an
OpenHarmony FFI library is a prebuilt ELF for x86_64-linux-ohos, so the only way
to run it is through WSL with the OHOS musl loader. :mod:`ohvul.poc_verify` can
compile and run on the host it sits on, so this module hands the heavy lifting
to ``tools/harness/ohos/run_real.sh`` and brings the answer back as a frame.

The frame is what makes a crash evidence: a draft can SIGSEGV inside the
library and still be wrong. On the UDMF case (2026-10-21) the first draft
guessed ``CParameters`` and crashed in ``SetDataParameters``, two lines above
the call the finding named. Exit code 139 plus "inside the library" read as
confirmed; the symbolized frame did not.

Nothing here decides whether the frame is the claimed one beyond a plain
comparison — that judgement belongs to ``poc_verify.verdict_for``.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .poc_verify import _frame_matches

SCRIPT = Path(__file__).resolve().parent.parent / 'tools' / 'harness' / 'ohos' / 'run_real.sh'

DEFAULT_DISTRO = 'Ubuntu'
DEFAULT_TIMEOUT = 600


class RealLibraryError(RuntimeError):
    """The WSL side could not be reached or the runner failed outright."""


def _wsl_command(distro: str, script: str, args: list[str]) -> list[str]:
    return ['wsl.exe', '-d', distro, '--', 'bash', script, *args]


def _to_posix(path: str | Path) -> str:
    """Windows drive letters are not usable inside WSL; /mnt/<drive>/… is."""
    raw = str(path).replace('\\', '/')
    if len(raw) > 1 and raw[1] == ':':
        return '/mnt/' + raw[0].lower() + raw[2:]
    return raw


def resolve_frame(client: Path, library_rel: str, *, oh_root: str,
                  build_output: str, evidence_dir: Path | None = None,
                  soname_alias: str | None = None, distro: str = DEFAULT_DISTRO,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Build `client`, run it against `library_rel`, and attribute any crash.

    Returns the runner's JSON plus a normalised ``frames`` list
    (``{function, file, line}`` per inline frame, innermost first).
    """
    evidence = Path(evidence_dir) if evidence_dir else Path(tempfile.mkdtemp(prefix='wt-real-'))
    evidence.mkdir(parents=True, exist_ok=True)
    script = _to_posix(SCRIPT)
    args = [_to_posix(oh_root), _to_posix(build_output), _to_posix(client),
            library_rel, _to_posix(evidence)]
    if soname_alias:
        args.append(soname_alias)
    try:
        completed = subprocess.run(_wsl_command(distro, script, args),
                                   capture_output=True, text=True,
                                   timeout=timeout, errors='replace')
    except (OSError, subprocess.SubprocessError) as exc:
        raise RealLibraryError(f'{type(exc).__name__}: {exc}') from exc
    if completed.returncode != 0:
        raise RealLibraryError(
            f'runner exited {completed.returncode}: {(completed.stderr or "")[-300:]}')
    payload = completed.stdout.strip().splitlines()
    if not payload:
        raise RealLibraryError(f'runner produced no JSON: {(completed.stderr or "")[-300:]}')
    try:
        data = json.loads(payload[-1])
    except ValueError as exc:
        raise RealLibraryError(f'unparsable runner output: {payload[-1][:200]}') from exc
    data.setdefault('frames', [])
    data['evidence_dir'] = str(evidence)
    return data


def frame_lands(data: dict, expected_function: str | None = None,
                expected_line: int | None = None) -> bool:
    """True when the symbolized chain contains the claimed frame.

    The chain is innermost-first, so ``basic_string::__init`` ->
    ``basic_string(nullptr)`` -> ``FfiUDMFSetProperties`` counts: the outer
    entry is the call the finding named. A different function, or the right
    function at a different line, does not.
    """
    if not expected_function:
        return True
    for frame in data.get('frames') or []:
        # addr2line marks a CFI frame with a ".cfi" suffix, and a demangled
        # symbol carries its namespace, so the comparison is the same one
        # poc_verify uses: equal, or one contained in the other.
        if not _frame_matches({'function': expected_function},
                              {'function': frame.get('function')}):
            continue
        if expected_line is None:
            return True
        try:
            if int(frame.get('line') or 0) == int(expected_line):
                return True
        except (TypeError, ValueError):
            continue
    return False


def describe(data: dict) -> str:
    """One-line human summary of what the real run actually hit."""
    if not data.get('built'):
        return f"did not build: {(data.get('build_error') or '')[-160:]}"
    if not data.get('crashed'):
        return f"ran without crashing (exit {data.get('exit')})"
    chain = data.get('frames') or []
    where = ' -> '.join(f"{c.get('function')} ({Path(c.get('file') or '?').name}:{c.get('line')})"
                        for c in chain) or 'no symbolized frame'
    agree = '' if data.get('offsets_agree', True) else ' [offsets disagreed across rounds]'
    return f"crashed at {data.get('offset')} in {where}{agree}"


def runtime_hook(library_rel: str, *, oh_root: str, build_output: str,
                 evidence_dir: Path | None = None, soname_alias: str | None = None,
                 distro: str = DEFAULT_DISTRO, timeout: int = DEFAULT_TIMEOUT,
                 workdir: Path | None = None):
    """A ``llm_poc.generate_poc_llm`` runtime gate backed by the real library.

    ``hook(code, finding) -> (landed, note)``: the draft is written out,
    compiled and run under musl, and the crash frame is compared with the
    function (and line) the finding names.
    """
    scratch = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix='wt-runtime-hook-'))
    scratch.mkdir(parents=True, exist_ok=True)
    base_evidence = Path(evidence_dir) if evidence_dir else scratch / 'evidence'

    def hook(code: str, finding: dict) -> tuple[bool, str]:
        expected_function = (finding.get('function') or '').strip()
        try:
            expected_line = int(finding.get('line') or 0) or None
        except (TypeError, ValueError):
            expected_line = None
        draft = scratch / f"draft_{abs(hash(code)) % 10**8}.c"
        draft.write_text(code, encoding='utf-8')
        data = resolve_frame(draft, library_rel, oh_root=oh_root,
                             build_output=build_output,
                             evidence_dir=base_evidence / draft.stem,
                             soname_alias=soname_alias, distro=distro,
                             timeout=timeout)
        note = describe(data)
        if not data.get('crashed'):
            return False, 'no_crash: ' + note
        if not frame_lands(data, expected_function, expected_line):
            return False, ('crash_elsewhere: expected '
                           f'{expected_function}:{expected_line}, observed ' + note)
        return True, ('landed: ' + note)

    return hook
