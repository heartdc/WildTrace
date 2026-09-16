"""Prepare or explicitly run ONE pinned public cJSON regression case.

Preparation never builds/runs a target. Execution is Linux-only and requires
bubblewrap, a namespace self-check and --execute-authorized. No unsandboxed
fallback, arbitrary command input, downloads or product-wide impact claims.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from ohvul.engine_adapter import engine_result_to_audit_result
from ohvul.engine_profile import _git
from ohvul.report.schema import build_audit_report, validate_report_against_result
from ohvul.review_queue import checked_path, read_bounded, exclusive_json
from ohvul.source_snapshot import source_snapshot

CASE = PROJECT / 'cases/cjson_merge_alias'
COPIES = ('cJSON.c', 'cJSON_Utils.c', 'cJSON.h', 'cJSON_Utils.h', 'LICENSE',
          'BUILD.gn', 'README.OpenSource')
OLD = b'        cJSON_Delete(target);\n        return cJSON_Duplicate(patch, 1);'
NEW = (b'        cJSON *duplicate = cJSON_Duplicate(patch, 1);\n'
       b'        cJSON_Delete(target);\n        return duplicate;')
CONTROLS = ('independent', 'detached', 'object-merge', 'object-delete')
ALIASES = ('subtree', 'scalar-subtree', 'self-array')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def patch_source(raw: bytes) -> bytes:
    newline = b'\r\n' if b'\r\n' in raw else b'\n'
    before, after = OLD.replace(b'\n', newline), NEW.replace(b'\n', newline)
    if raw.count(before) != 1:
        raise ValueError('Expected exactly one original non-object merge branch')
    return raw.replace(before, after, 1)


def local_path(value: str | Path) -> Path:
    text = str(value)
    if os.name == 'posix' and re.match(r'^[A-Za-z]:[\\/]', text):
        text = '/mnt/' + text[0].lower() + '/' + text[3:].replace('\\', '/')
    return checked_path(text)


def prepare(source: Path, output: Path) -> dict:
    source, output = local_path(source), local_path(output)
    spec = json.loads(read_bounded(CASE / 'case.json', 65536))
    if output.exists() or not output.parent.is_dir() or output.is_relative_to(source):
        raise ValueError('Use a new output directory outside the source tree')
    head = _git(source, 'rev-parse', 'HEAD').strip()
    if head != spec['expected_commit'] or _git(source, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Expected the pinned clean cJSON checkout')
    raw = {name: read_bounded(source / name, 2 * 1024 * 1024) for name in COPIES}
    for name, digest in spec['expected_source_sha256'].items():
        if sha(raw[name]) != digest:
            raise ValueError('Pinned source byte mismatch: ' + name)
    patched = patch_source(raw['cJSON_Utils.c'])
    snapshot = source_snapshot(source)
    # Explicit source review, NOT a result claimed to come from the detector.
    finding = {'source': 'case-source-review', 'rule': 'known.mergepatch.nonobject-alias',
        'cwe_candidate': 'CWE-416', 'cwe_mapping_source': 'reviewed_ownership_sequence',
        'cwe_mapping_version': '1', 'location': {'file': 'cJSON_Utils.c', 'line': 1328},
        'description': 'Deleting target invalidates a borrowed non-object patch before duplication',
        'status': 'candidate', 'evidence': {'review_origin': 'public_issue_informed_source_review',
            'cve_reference': spec['public_cve_reference'], 'new_discovery': False,
            'preconditions': ['patch is target or an owned non-object subtree',
                              'caller does not separately free consumed target/patch'],
            'source_sha256': {n: sha(raw[n]) for n in COPIES},
            'code_excerpt': raw['cJSON_Utils.c'].decode().splitlines()[1320:1331],
            'security_boundary': 'object lifetime', 'product_reachability': 'unknown'}}
    result = engine_result_to_audit_result({'engine': 'case-source-review', 'engine_version': '1',
        'source_root': str(source), 'status': 'completed', 'findings': [finding],
        'files_scanned': 2, 'input_errors': []}, source_root=source, source_snapshot_sha256=snapshot)
    result['case_scope'] = {'runtime_status': 'not_run', 'new_discovery': False,
                            'product_impact_verified': False, 'automated_detection': False}
    report = build_audit_report(result)
    validate_report_against_result(report, result)
    output.mkdir()
    for variant in ('original', 'patched'):
        folder = output / variant
        folder.mkdir()
        for name, content in raw.items():
            if variant == 'patched' and name == 'cJSON_Utils.c':
                content = patched
            with (folder / name).open('xb') as stream:
                stream.write(content)
    poc = read_bounded(CASE / 'poc.c', 65536)
    (output / 'poc.c').write_bytes(poc)
    diff = ''.join(difflib.unified_diff(raw['cJSON_Utils.c'].decode().splitlines(True),
        patched.decode().splitlines(True), fromfile='a/cJSON_Utils.c', tofile='b/cJSON_Utils.c'))
    (output / 'patch.diff').write_bytes(diff.encode())
    exclusive_json(output / 'result.json', result)
    exclusive_json(output / 'report.candidate.json', report)
    if source_snapshot(source) != snapshot or _git(source, 'rev-parse', 'HEAD').strip() != head:
        raise ValueError('Source changed while preparing case; no completion manifest published')
    artifact_names = [f'{variant}/{name}' for variant in ('original', 'patched') for name in COPIES]
    artifact_names += ['poc.c', 'patch.diff', 'result.json', 'report.candidate.json']
    manifest = {'schema': 'cjson-case-prepared-0.1', 'source_root': str(source), 'source_commit': head,
        'source_snapshot_sha256': snapshot, 'spec': spec,
        'artifacts': {n: sha((output / n).read_bytes()) for n in artifact_names},
        'runtime_status': 'not_run', 'target_executed': False, 'confirmed_vulnerabilities': 0}
    exclusive_json(output / 'prepared.json', manifest)
    return manifest


def verify_prepared(folder: Path) -> dict:
    folder = local_path(folder)
    doc = json.loads(read_bounded(folder / 'prepared.json', 1024 * 1024))
    expected = {f'{variant}/{name}' for variant in ('original', 'patched') for name in COPIES}
    expected.update(('poc.c', 'patch.diff', 'result.json', 'report.candidate.json'))
    if doc.get('schema') != 'cjson-case-prepared-0.1' or set(doc['artifacts']) != expected:
        raise ValueError('Unexpected prepared artifact set')
    spec = json.loads(read_bounded(CASE / 'case.json', 65536))
    if doc.get('spec') != spec or doc.get('source_commit') != spec['expected_commit']:
        raise ValueError('Case specification or source commit was substituted')
    for name, digest in doc['artifacts'].items():
        if sha(read_bounded(folder / name, 2 * 1024 * 1024)) != digest:
            raise ValueError('Prepared artifact changed: ' + name)
    original = read_bounded(folder / 'original/cJSON_Utils.c', 2 * 1024 * 1024)
    if patch_source(original) != read_bounded(folder / 'patched/cJSON_Utils.c', 2 * 1024 * 1024):
        raise ValueError('Patch is not exactly the reviewed change')
    source = local_path(doc['source_root'])
    for name in COPIES:
        if read_bounded(source / name, 2 * 1024 * 1024) != read_bounded(folder / 'original' / name, 2 * 1024 * 1024):
            raise ValueError('Original source copy differs from pinned checkout')
        if name != 'cJSON_Utils.c' and (folder / 'original' / name).read_bytes() != (folder / 'patched' / name).read_bytes():
            raise ValueError('Unreviewed file changed in patch copy')
    for name, digest in spec['expected_source_sha256'].items():
        if sha((folder / 'original' / name).read_bytes()) != digest:
            raise ValueError('Pinned source content changed')
    if (folder / 'poc.c').read_bytes() != read_bounded(CASE / 'poc.c', 65536):
        raise ValueError('Reproducer differs from reviewed case')
    if _git(source, 'rev-parse', 'HEAD').strip() != doc['source_commit']:
        raise ValueError('Original repository commit changed')
    if source_snapshot(source) != doc['source_snapshot_sha256']:
        raise ValueError('Original checkout changed')
    return doc


def classify(returncode: int, log: str, *, timed_out=False, output_limited=False) -> str:
    if timed_out or output_limited:
        return 'incomplete'
    access_trace = log.split('freed by thread', 1)[0]
    if (returncode != 0 and 'ERROR: AddressSanitizer: heap-use-after-free' in log
            and 'cJSON_Duplicate' in access_trace and 'merge_patch' in log):
        return 'library_uaf_observed'
    if returncode == 0 and 'CASE_OK ' in log and not any(x in log for x in (
            'ERROR: AddressSanitizer', 'ERROR: LeakSanitizer', 'runtime error:')):
        return 'functional_control_passed'
    return 'unexpected'


def sandbox(source: Path, binary_dir: Path, *, build: bool) -> list[str]:
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/home/airgap/llvm', '/opt/llvm', '--ro-bind', str(source), '/src',
        '--bind' if build else '--ro-bind', str(binary_dir), '/out',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--clearenv',
        '--setenv', 'PATH', '/opt/llvm/bin:/usr/bin', '--setenv', 'LANG', 'C',
        '--setenv', 'ASAN_SYMBOLIZER_PATH', '/opt/llvm/bin/llvm-symbolizer',
        '--setenv', 'ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1:symbolize=1',
        '--setenv', 'UBSAN_OPTIONS', 'halt_on_error=1:print_stacktrace=1', '--chdir', '/out']


def command(args: list[str], log_path: Path, seconds: int) -> dict:
    start = time.monotonic()
    timed_out = limited = False
    with log_path.open('xb') as log:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        while child.poll() is None:
            timed_out = time.monotonic() - start > seconds
            limited = log_path.stat().st_size > 2 * 1024 * 1024
            if timed_out or limited:
                os.killpg(child.pid, signal.SIGKILL)
                break
            time.sleep(0.05)
        rc = child.wait(timeout=5)
    raw = log_path.read_bytes()
    return {'command': args, 'exit_code': rc, 'seconds': time.monotonic() - start,
        'timed_out': timed_out, 'output_limited': limited, 'log': log_path.name,
        'log_sha256': sha(raw), 'classification': classify(rc, raw.decode('utf-8', 'replace'),
            timed_out=timed_out, output_limited=limited)}


def execute(folder: Path, authorized: bool) -> dict:
    if not authorized or os.name != 'posix':
        raise ValueError('Execution requires Linux and explicit --execute-authorized')
    folder = local_path(folder)
    doc = verify_prepared(folder)
    if not Path('/usr/bin/bwrap').is_file() or not Path('/home/airgap/llvm/bin/clang').is_file():
        raise ValueError('Required local bubblewrap/Clang unavailable; no fallback')
    logs = folder / 'runtime'
    logs.mkdir(exist_ok=False)
    probe_code = ("import os,json; print(json.dumps({'netns':os.readlink('/proc/self/ns/net'),"
                  "'pidns':os.readlink('/proc/self/ns/pid'),'host_mount':os.path.exists('/mnt/c'),"
                  "'home':os.path.exists('/home'),'netdev':open('/proc/net/dev').read()}))")
    probe = command(sandbox(folder / 'original', logs, build=False) +
                    ['/usr/bin/python3', '-c', probe_code], logs / 'isolation.log', 15)
    if probe['exit_code'] != 0:
        raise ValueError('Isolation probe failed; no compiler or target invoked')
    isolation = json.loads((logs / 'isolation.log').read_text())
    interfaces = re.findall(r'^\s*([^\s:]+):', isolation['netdev'], re.M)
    if (isolation['host_mount'] or isolation['home'] or
            set(interfaces) - {'lo'} or
            isolation['netns'] == os.readlink('/proc/self/ns/net') or
            isolation['pidns'] == os.readlink('/proc/self/ns/pid')):
        raise ValueError('Namespace checks failed; no compiler or target invoked')
    version = command(sandbox(folder / 'original', logs, build=False) +
        ['/opt/llvm/bin/clang', '--no-default-config', '--version'], logs / 'compiler-version.log', 15)
    if version['exit_code'] or version['timed_out'] or version['output_limited']:
        raise ValueError('Compiler identity query failed; no target invoked')
    rows = []
    for variant, opt in (('original', '-O0'), ('independent', '-O1'), ('patched', '-O0')):
        source = folder / ('original' if variant == 'independent' else variant)
        bindir = logs / variant
        bindir.mkdir()
        compile_args = ['/usr/bin/prlimit', '--cpu=60', '--fsize=33554432', '--nproc=64', '--',
            '/opt/llvm/bin/clang', '--no-default-config', '-std=c99', opt, '-g',
            '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls', '-fsanitize=address,undefined',
            '-DCJSON_NESTING_LIMIT=128', '-I/src', '/src/cJSON.c', '/src/cJSON_Utils.c',
            '/out/poc.c', '-lm', '-o', '/out/probe']
        (bindir / 'poc.c').write_bytes((folder / 'poc.c').read_bytes())
        build = command(sandbox(source, bindir, build=True) + compile_args,
                        logs / ('build-' + variant + '.log'), 90)
        build.update(phase='build', variant=variant)
        rows.append(build)
        if build['exit_code'] or build['timed_out'] or build['output_limited']:
            exclusive_json(logs / 'incomplete.json', {'rows': rows, 'status': 'build_failed'})
            raise ValueError('Build failed; no success verdict')
        selections = ([('subtree', False)] * 3 + [(x, s) for x in CONTROLS for s in (False, True)]
                      if variant == 'original' else [('subtree', False)] if variant == 'independent'
                      else [(x, s) for x in ALIASES + CONTROLS for s in (False, True)])
        for i, (name, sensitive) in enumerate(selections):
            invocation = ['/usr/bin/prlimit', '--cpu=10', '--fsize=1048576', '--nproc=64', '--',
                          '/out/probe', name] + (['sensitive'] if sensitive else [])
            rec = command(sandbox(source, bindir, build=False) + invocation,
                          logs / f'{variant}-{i:02d}.log', 20)
            expected = ('library_uaf_observed' if variant in ('original', 'independent')
                        and name == 'subtree' else 'functional_control_passed')
            rec.update(phase='run', variant=variant, case=name, case_sensitive=sensitive,
                       expected=expected, passed=rec['classification'] == expected,
                       binary_sha256=sha((bindir / 'probe').read_bytes()))
            rows.append(rec)
    verify_prepared(folder)
    passed = all(r.get('passed', True) for r in rows)
    result = {'schema': 'cjson-observed-matrix-0.1', 'status': 'passed' if passed else 'failed',
        'prepared_sha256': sha((folder / 'prepared.json').read_bytes()), 'rows': rows,
        'isolation': isolation, 'compiler_version_record': version,
        'compiler_binary_sha256': sha(Path('/home/airgap/llvm/bin/clang').read_bytes()),
        'target_executed': True, 'public_known_case': True,
        'independent_scope': 'fresh build and namespace; same driver, not independent human review',
        'product_reachability': 'not_established', 'confirmed_product_vulnerabilities': 0,
        'limitations': ['No signed attestation; hashes bind local records only.',
                        'Namespace configuration is not an immutable VM image.',
                        'ASan requires large virtual address space; no hard RAM limit is asserted.',
                        'The non-object alias fix does not validate all MergePatch alias cases.']}
    exclusive_json(logs / 'acceptance.json', result)
    if not passed:
        raise ValueError('Unexpected reproduction/control result; inspect preserved logs')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'verify', 'run'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--execute-authorized', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.mode == 'prepare':
            if args.source is None or args.execute_authorized:
                raise ValueError('prepare requires source; no execution flag')
            value = prepare(args.source, args.output)
        elif args.mode == 'verify':
            if args.execute_authorized:
                raise ValueError('verify never executes targets')
            value = verify_prepared(args.output)
        else:
            value = execute(args.output, args.execute_authorized)
        print(json.dumps({'mode': args.mode, 'status': value.get('status', 'prepared_inputs_verified'),
                          'target_executed': value.get('target_executed', False)}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('CASE_STOPPED ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
