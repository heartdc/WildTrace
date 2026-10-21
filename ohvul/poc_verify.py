"""Compile-and-run verification for generated PoCs (steps 3 and 4 of the gate).

The drafting pipeline (`ohvul.llm_poc`) only does text-level checks: it can tell
a copied target function from a library call, but it cannot tell whether the
code compiles, links against the real project, or actually crashes inside the
shipped code. Those are the last two steps and they live here.

    python -m ohvul.poc_verify <pocs_dir> --source <source_root> \
        --output <verify_dir> [--link cJSON.c --link cJSON_Utils.c] \
        [--findings findings.json]

Verdicts, weakest to strongest:
    copied_target  the PoC re-implements the vulnerable function; a crash here
                   is a tautology and is never evidence
    self_contained compiles without the project, no target redefinition: the
                   crash (if any) is in the PoC's own logic
    real_link      links the project sources / calls the public API; a crash in
                   this class is the only kind that says something about cJSON

Exit code: 0 when every PoC was compiled and run (whatever the outcome),
1 when at least one build failed, 2 on argument/environment errors.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# 0xC0000005 access violation on Windows; 139/134/136 are the POSIX signals
CRASH_CODES = {3221225477, -1073741819, 139, 134, 136}
COMPILER_ENV = 'WILDTRACE_CC'
SANITIZER_FLAGS = ('-fno-sanitize=all', '-fno-sanitize-trap=all')


def discover_compiler(explicit: str | None = None) -> list[str] | None:
    """Command prefix used to compile. zig cc first: it ships as a pip wheel,
    needs no admin rights, and the MinGW build on some Windows boxes is
    quarantined by Defender (WinError 225)."""
    if explicit:
        return explicit.split()
    env = os.environ.get(COMPILER_ENV)
    if env:
        return env.split()
    try:
        import ziglang  # optional dependency, only for verification
        zig = Path(ziglang.__file__).parent / ('zig.exe' if os.name == 'nt' else 'zig')
        if zig.exists():
            return [str(zig), 'cc']
    except Exception:
        pass
    for name in (('gcc', 'clang', 'cc') if os.name == 'nt' else ('cc', 'gcc', 'clang')):
        found = shutil.which(name)
        if found:
            return [found]
    return None


def classify_poc(code: str, function: str = '', project_headers=()) -> str:
    """Text-level class. Uses llm_poc's definition detector so the drafting
    gate and the verification step cannot disagree about what 'copied' means.

    ``real_link`` requires a quoted project include (or one of the explicitly
    supplied header names): that is the shape where a crash happens inside the
    library instead of inside the PoC's own copy.
    """
    from .llm_poc import _defines_function
    if function and _defines_function(code, function):
        return 'copied_target'
    has_main = 'int main' in code or 'void main' in code
    if not has_main:
        return 'build_failed'
    quoted = set(re.findall(r'#\s*include\s*"([^"]+)"', code))
    for header in project_headers:
        if f'<{header}>' in code or f'"{header}"' in code:
            quoted.add(header)
    return 'real_link' if quoted else 'self_contained'


def compile_poc(poc: Path, output_dir: Path, compiler: list[str], *,
                link_sources=(), include_dirs=(), timeout: int = 120,
                retries: int = 1, force_include: Path | None = None,
                defines=(), object_only: bool = False):
    suffix = '.o' if object_only else ('.exe' if os.name == 'nt' else '')
    exe = output_dir / (poc.stem + suffix)
    cmd = list(compiler) + ['-O0', '-g']
    if 'zig' in Path(compiler[0]).name.lower():
        cmd += list(SANITIZER_FLAGS)
    cmd += [f'-D{name}' for name in defines]
    if force_include:
        # An instrumentation harness is injected, not edited into the draft:
        # the PoC under test stays byte-identical to what the model wrote.
        cmd += ['-include', str(force_include)]
    cmd.append(str(poc))
    for directory in include_dirs:
        cmd += ['-I', str(directory)]
    if object_only:
        cmd += ['-c']
    cmd += [str(source) for source in link_sources]
    cmd += ['-o', str(exe)]
    error = ''
    for attempt in range(retries + 1):
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=timeout, errors='replace')
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f'{type(exc).__name__}: {exc}', ' '.join(cmd), None
        ok = completed.returncode == 0 and exe.exists()
        error = (completed.stderr or '').strip()[-800:]
        if ok:
            return True, error, ' '.join(cmd), exe
        # zig rebuilds the mingw CRT on first use; two builds in quick
        # succession can collide and report SubCompilationFailed. It is
        # transient — a second attempt succeeds — so do not spend a model
        # rewrite on it.
        if 'SubCompilationFailed' in error and attempt < retries:
            continue
        break
    return False, error, ' '.join(cmd), None


_UNDEFINED_PATTERNS = (
    re.compile(r"undefined symbol:\s*([A-Za-z_]\w*)"),
    re.compile(r"undefined reference to [`'\"]([^`'\"]+)[`'\"]"),
    re.compile(r"unresolved external symbol\s+([A-Za-z_]\w*)"),
)


def parse_undefined_symbols(stderr: str) -> list[str]:
    """Symbol names the linker could not find, in link order, deduplicated."""
    found, seen = [], set()
    for pattern in _UNDEFINED_PATTERNS:
        for name in pattern.findall(stderr or ''):
            name = name.lstrip('_') if name.startswith('__imp_') else name
            if name and name not in seen:
                seen.add(name)
                found.append(name)
    return found


def _source_candidates(source_root: Path, finding_file: str | None, limit: int = 400):
    """Project sources to search for a symbol definition.

    Narrows to the finding's own directory first: a PoC for cJSON_Utils.c only
    ever needs files next to it, and a full-tree grep would be pointless.
    """
    roots = []
    if finding_file:
        parent = (source_root / finding_file).parent
        if parent.is_dir():
            roots.append(parent)
    roots.append(source_root)
    seen = 0
    for root in roots:
        for path in root.rglob('*'):
            if path.suffix not in ('.c', '.cc', '.cpp'):
                continue
            yield path
            seen += 1
            if seen >= limit:
                return


def resolve_link_sources(poc: Path, source_root: Path, *, compiler=None,
                         include_dirs=(), link_sources=(), finding_file=None,
                         output_dir: Path | None = None, max_rounds: int = 3,
                         timeout: int = 180, force_include: Path | None = None,
                         defines=()):
    """Link by following the linker's own complaints.

    A draft that calls ``cJSON_Parse`` does not say that ``cJSON.c`` has to be
    linked, and a finding in ``cJSON_Utils.c`` needs both. Rather than asking
    the caller to hand-write the link set per component, compile, read the
    undefined symbols, add whichever sibling source defines them, and retry
    (bounded). Returns ``(built, stderr, link_sources_used)``.
    """
    from .llm_poc import _defines_function

    compiler = compiler or discover_compiler()
    if not compiler:
        return False, 'no C compiler found', list(link_sources)
    workdir = output_dir or poc.parent
    links = list(link_sources)
    error = ''
    for _round in range(max_rounds):
        ok, error, _cmd, _exe = compile_poc(
            poc, workdir, compiler, link_sources=links,
            include_dirs=[source_root, *include_dirs], timeout=timeout,
            force_include=force_include, defines=defines)
        if ok:
            return True, error, links
        symbols = parse_undefined_symbols(error)
        if not symbols:
            return False, error, links
        additions = []
        for candidate in _source_candidates(source_root, finding_file):
            try:
                text, _truncated = _read_capped(candidate)
            except OSError:
                continue
            if any(_defines_function(text, symbol) for symbol in symbols):
                if candidate not in links and candidate not in additions:
                    additions.append(candidate)
            if len(additions) >= 4:
                break
        if not additions:
            return False, error, links
        links.extend(additions)
    return False, error, links


def _read_capped(path: Path, limit: int = 256 * 1024):
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    return data[:limit].decode('utf-8', errors='replace'), len(data) > limit


def run_poc(exe: Path, timeout: int = 10):
    started = time.perf_counter()
    try:
        completed = subprocess.run([str(exe)], capture_output=True, text=True,
                                   timeout=timeout, errors='replace')
        code, out, err = completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired:
        code, out, err = None, '', 'timeout'
    except OSError as exc:
        code, out, err = None, '', f'{type(exc).__name__}: {exc}'
    return {'exit_code': code, 'crashed': code in CRASH_CODES,
            'stdout': (out or '')[-400:], 'stderr': (err or '')[-400:],
            'seconds': round(time.perf_counter() - started, 2)}


def compile_source(code: str, workdir: Path, *, compiler=None, link_sources=(),
                   include_dirs=(), name: str = 'draft', timeout: int = 120):
    """Compile a draft straight from memory — the hook llm_poc uses to feed
    compiler errors back to the model. Returns ``(built, stderr)``."""
    workdir.mkdir(parents=True, exist_ok=True)
    source = workdir / f'{name}.c'
    source.write_text(code, encoding='utf-8')
    ok, error, _cmd, _exe = compile_poc(
        source, workdir, compiler or discover_compiler() or [],
        link_sources=link_sources, include_dirs=include_dirs, timeout=timeout)
    return ok, error


# Patterns whose failure mode is an immediate, detectable fault even on a plain
# build. The rest (use-after-free, overflow) can corrupt memory silently, so a
# "did not crash" observation means nothing without a memory checker.
_FAULTS_WITHOUT_CHECKER = {'P6_null_deref', 'P9_format_string'}
_SILENT_CORRUPTION = {'P8_use_after_free', 'P8_cross_uaf', 'P8_double_free',
                      'P4_unbounded_copy', 'P5_stack_overflow', 'P7_alloc_overflow'}

_MEMORY_CHECK_CACHE: dict[str, bool] = {}


def memory_checker_available(compiler: list[str] | None = None,
                             workdir: Path | None = None) -> bool:
    """Can this toolchain build with AddressSanitizer?

    On Windows/mingw the ASan runtime is missing (``undefined symbol:
    __asan_report_load8``), so UAF and overflow bugs run silently and a
    "no crash" observation must not be promoted to a refutation.
    """
    compiler = compiler or discover_compiler()
    if not compiler:
        return False
    key = ' '.join(compiler)
    if key in _MEMORY_CHECK_CACHE:
        return _MEMORY_CHECK_CACHE[key]
    probe_dir = workdir or Path(tempfile.gettempdir()) / 'wildtrace_asan_probe'
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe = probe_dir / 'probe.c'
    probe.write_text('int main(void){return 0;}\n', encoding='utf-8')
    exe = probe_dir / ('probe' + ('.exe' if os.name == 'nt' else ''))
    cmd = list(compiler) + ['-fsanitize=address', str(probe), '-o', str(exe)]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=180, errors='replace')
        available = completed.returncode == 0 and exe.exists()
    except (OSError, subprocess.SubprocessError):
        available = False
    _MEMORY_CHECK_CACHE[key] = available
    return available


def _frame_matches(expected: dict | None, observed: dict | None) -> bool:
    """Function-level frame match.

    Offset equality is too strict across builds (the same source line moves when
    the binary changes), while file+line alone fails for inlined frames. Compare
    the settled symbol: an observed ``basic_string::__init`` inlined from
    ``FfiUDMFSetProperties`` still counts as the claimed function only when the
    resolver reports the outer symbol, which is why the resolver contract asks
    for the frame that owns the call, not the innermost one.
    """
    if not expected or not observed:
        return True
    want = (expected.get('function') or '').strip()
    got = (observed.get('function') or '').strip()
    if not want or not got:
        return True
    return want == got or want in got or got in want


def verdict_for(result: dict, *, memory_checks: bool = True,
                expected: dict | None = None,
                observed: dict | None = None) -> tuple[str, str]:
    """Three-state verdict in the spirit of an independent re-review pass.

    ``confirmed``   the PoC links the real project and the crash happens inside
                    library code — evidence about the shipped code, not about a
                    copy of it
    ``refuted``     the PoC links the real project, runs, and the library does
                    not crash: this candidate is not reachable that way
    ``undetermined`` nothing can be concluded: did not build, did not run, or
                    the crash sits in the PoC's own copy (a tautology)

    The distinction matters because "no crash" from a real-link client is a
    result, while "no crash" from a copied body says nothing at all.
    """
    if not result.get('compiled'):
        return 'undetermined', 'build_failed'
    if result.get('exit_code') is None:
        return 'undetermined', 'did_not_run'
    kind = result.get('kind')
    if kind == 'copied_target':
        return 'undetermined', 'copied_target_crash_is_tautology'
    if kind == 'real_link':
        if result.get('crashed'):
            # A crash inside the library is necessary but not sufficient: it has
            # to land on the claimed frame. Observed on the UDMF case
            # (2026-10-21): a draft with a guessed ABI crashed in
            # SetDataParameters while the finding named the tag conversion one
            # line below, and "exit 139 + inside the library" would have called
            # that confirmed.
            if observed is not None and not _frame_matches(expected, observed):
                return 'wrong_site', 'crash_at_unrelated_frame'
            return 'confirmed', 'crash_inside_library'
        pattern = result.get('pattern') or ''
        if not memory_checks and pattern in _SILENT_CORRUPTION:
            # The code ran, but a silent UAF/overflow would look exactly like
            # this. Observed on CVE-2026-87933: the same PoC returns 0 on the
            # default heap and SIGSEGVs under a quarantining allocator.
            return 'undetermined', 'no_crash_without_memory_checker'
        return 'refuted', 'real_link_no_crash'
    if kind == 'self_contained':
        return 'undetermined', 'not_linked_against_library'
    return 'undetermined', 'unknown_shape'


def verify(pocs_dir: Path, source_root: Path, output_dir: Path, *,
           findings: dict | None = None, link=(), include_dirs=(),
           include_headers=(), compiler: list[str] | None = None,
           timeout: int = 10, harness: Path | None = None,
           guarded_heap: Path | None = None,
           frames: dict | None = None) -> dict:
    """Compile and run every ``*.c`` in ``pocs_dir``; never raises per-PoC."""
    output_dir.mkdir(parents=True, exist_ok=True)
    compiler = compiler or discover_compiler()
    if not compiler:
        raise RuntimeError('no C compiler found: install ziglang, or set '
                           f'{COMPILER_ENV}=<compiler command>')
    by_location = {}
    if findings:
        for item in findings.get('findings', []):
            key = (str(item.get('file', '')).replace('\\', '/'), item.get('line'))
            by_location[key] = item

    # llm_poc writes the target of each draft next to it; without it the
    # copied-target class degrades to include-based detection only
    meta_by_poc = {}
    summary_path = pocs_dir / 'llm_poc_summary.json'
    if summary_path.exists():
        try:
            data = json.loads(summary_path.read_text(encoding='utf-8'))
            for item in data.get('results', []):
                if item.get('poc_file'):
                    meta_by_poc[item['poc_file']] = (
                        str(item.get('file', '')).replace('\\', '/'), item.get('line'))
        except (ValueError, OSError):
            meta_by_poc = {}
    project_headers = {Path(h).name for h in include_headers}

    rows = []
    for poc in sorted(pocs_dir.glob('*.c')):
        code = poc.read_text(encoding='utf-8', errors='replace')
        rows.append({'poc': poc.name, 'code': code})

    # Guarded heap: redirect the standard allocator names at the preprocessor
    # level (lld has no --wrap, and mingw has no ASan runtime). The harness
    # object itself is built without the defines so it can reach the CRT.
    defines, harness_objects = [], []
    force_include = harness
    if guarded_heap:
        guard_c = guarded_heap / 'guarded_heap.c'
        guard_h = guarded_heap / 'guarded_heap.h'
        if not guard_c.is_file() or not guard_h.is_file():
            raise RuntimeError(f'guarded heap not found under {guarded_heap}')
        built, error, _cmd, obj = compile_poc(
            guard_c, output_dir, compiler, include_dirs=[guarded_heap],
            object_only=True)
        if not built:
            raise RuntimeError(f'guarded heap failed to build: {error[-300:]}')
        harness_objects.append(obj)
        force_include = guard_h
        defines = ['malloc=wt_guard_malloc', 'free=wt_guard_free',
                   'realloc=wt_guard_realloc', 'calloc=wt_guard_calloc']

    # A harness that quarantines freed memory is itself a memory checker, so a
    # "no crash" observation becomes meaningful again.
    memory_checks = bool(force_include) or memory_checker_available(
        compiler, output_dir / '_asan_probe')

    results = []
    for row in rows:
        poc = pocs_dir / row['poc']
        # the finding this draft targets, so "copied target" is judged against
        # the same function name the drafting gate used
        meta = meta_by_poc.get(row['poc'])
        matched = by_location.get(meta) if meta else None
        function = (matched or {}).get('function', '')
        kind = classify_poc(row['code'], function, project_headers)
        if link:
            ok, error, cmd, exe = compile_poc(
                poc, output_dir, compiler, link_sources=[*harness_objects, *link],
                include_dirs=[source_root, *include_dirs],
                force_include=force_include, defines=defines)
            used_links = [*harness_objects, *link]
        else:
            # No explicit link set: let the linker name what it is missing, so
            # a caller never has to know that cJSON_Utils.c needs cJSON.c too.
            ok, error, used_links = resolve_link_sources(
                poc, source_root, compiler=compiler, include_dirs=list(include_dirs),
                output_dir=output_dir, finding_file=(matched or {}).get('file'),
                force_include=force_include, defines=defines,
                link_sources=list(harness_objects))
            cmd = ''
            exe = output_dir / (poc.stem + ('.exe' if os.name == 'nt' else ''))
            if not ok:
                exe = None
        result = {'poc': row['poc'], 'function': function,
                  'pattern': (matched or {}).get('pattern', ''), 'kind': kind,
                  'compiled': ok, 'compile_error': '' if ok else error,
                  'command': cmd, 'link_sources': [Path(p).name for p in used_links],
                  'exit_code': None, 'crashed': None}
        if ok:
            result.update(run_poc(exe, timeout))
        # An external resolver (gdb + addr2line) can hand in the settled frame
        # per draft; without it the verdict stays at "crash inside the library"
        # and cannot tell the claimed site from an unrelated one.
        observed = (frames or {}).get(row['poc'])
        if observed:
            result['frame'] = observed
        expected = {'function': function, 'line': (matched or {}).get('line')}
        result['verdict'], result['verdict_reason'] = verdict_for(
            result, memory_checks=memory_checks,
            expected=expected if function else None,
            observed=observed)
        results.append(result)

    summary = {
        'pocs_dir': str(pocs_dir),
        'source_root': str(source_root),
        'compiler': ' '.join(compiler),
        'memory_checks': memory_checks,
        'harness': str(force_include) if force_include else '',
        'guarded_heap': str(guarded_heap) if guarded_heap else '',
        'total': len(results),
        'compiled': sum(1 for r in results if r['compiled']),
        'ran': sum(1 for r in results if r['exit_code'] is not None),
        'crashed': sum(1 for r in results if r['crashed']),
        'real_link': sum(1 for r in results if r['kind'] == 'real_link' and r['crashed']),
        'evidence_grade': sum(1 for r in results
                              if r['kind'] == 'real_link' and r['crashed']),
        'confirmed': sum(1 for r in results if r['verdict'] == 'confirmed'),
        'refuted': sum(1 for r in results if r['verdict'] == 'refuted'),
        'undetermined': sum(1 for r in results if r['verdict'] == 'undetermined'),
        'wrong_site': sum(1 for r in results if r['verdict'] == 'wrong_site'),
        'results': results,
    }
    (output_dir / 'poc_verification.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pocs_dir', type=Path)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--findings', type=Path, default=None,
                        help='findings.json the drafts came from (enables the '
                             'copied-target check by function name)')
    parser.add_argument('--link', action='append', default=[],
                        help='extra source files to link, relative to --source')
    parser.add_argument('--include', action='append', default=[],
                        help='extra include directory')
    parser.add_argument('--header', action='append', default=[],
                        help='project header name that makes a draft "real_link"')
    parser.add_argument('--compiler', default=None,
                        help=f'compiler command; default: {COMPILER_ENV} or zig cc')
    parser.add_argument('--guarded-heap', type=Path, default=None,
                        help='directory with guarded_heap.c/.h: redirects '
                             'malloc/free onto quarantined pages so a UAF faults '
                             'on a plain Windows build')
    parser.add_argument('--harness', type=Path, default=None,
                        help='header force-included into every draft, e.g. '
                             'tools/harness/guarded_heap.h (quarantining allocator)')
    parser.add_argument('--frames', type=Path, default=None,
                        help='JSON map {poc filename: {function,file,line,offset}} '
                             'from an external frame resolver; a crash whose '
                             'frame is not the claimed function becomes wrong_site')
    parser.add_argument('--timeout', type=int, default=10)
    args = parser.parse_args(argv)

    findings = json.loads(args.findings.read_text(encoding='utf-8')) \
        if args.findings else None
    link = [args.source / item for item in args.link]
    try:
        summary = verify(args.pocs_dir, args.source, args.output,
                         findings=findings, link=link,
                         include_dirs=args.include,
                         include_headers=args.header, compiler=None,
                         timeout=args.timeout, harness=args.harness,
                         guarded_heap=args.guarded_heap,
                         frames=(json.loads(args.frames.read_text(encoding='utf-8'))
                                 if args.frames else None))
    except RuntimeError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

    for row in summary['results']:
        print(f"  {row['poc'][:52]:52s} {row['kind']:15s} "
              f"{row['verdict']:13s} {row['verdict_reason']}")
    print(f"\ntotal {summary['total']} | compiled {summary['compiled']} | "
          f"crashed {summary['crashed']} | confirmed {summary['confirmed']} | "
          f"refuted {summary['refuted']} | wrong_site {summary['wrong_site']} | "
          f"undetermined {summary['undetermined']}")
    print(f"report: {args.output / 'poc_verification.json'}")
    return 0 if summary['compiled'] == summary['total'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
