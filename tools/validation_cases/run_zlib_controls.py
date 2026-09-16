"""Opt-in, isolated execution of the existing fixed-input zlib regression case.

Uses ONLY the existing pinned local revision. No downloads, Git mutations,
upstream build scripts, LLM requests, or vulnerable-source reconstruction.
Successful controls are not a vulnerability finding or proof of a historical fix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
from ohvul.compiler_analysis import _invoke
from ohvul.engine_adapter import windows_to_wsl_path
from ohvul.engine_profile import _git
from ohvul.review_queue import checked_path, read_bounded, decode_json, exclusive_json
from ohvul.source_scope import local_input_path

PIN = '7d1c4cdd5b5396ed14e60691713d5543a523fd12'
DEFAULT_ROOT = Path('C:/Projects/OpenHarmony/third_party/zlib')
SOURCES = ('adler32.c', 'crc32.c', 'inflate.c', 'inffast.c', 'inftrees.c', 'zutil.c')
HEADERS = ('zlib.h', 'zconf.h', 'zutil.h', 'inflate.h', 'inffast.h', 'inftrees.h',
           'inffixed.h', 'crc32.h', 'gzguts.h')
MODES = ('fragmented', 'whole', 'no-capture', 'full-capacity')
HARNESS = PROJECT / 'tools/validation_cases/zlib_gzip_extra_37434.c'
ASAN = ('detect_leaks=0:abort_on_error=1:allocator_may_return_null=1:'
        'hard_rss_limit_mb=512:quarantine_size_mb=16')
SANITIZER_MARKERS = ('ERROR: AddressSanitizer', 'SUMMARY: AddressSanitizer',
                     'runtime error:', 'UndefinedBehaviorSanitizer', 'LeakSanitizer')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def linux(path: Path) -> str:
    return windows_to_wsl_path(path) if os.name == 'nt' else str(path)


def capture_source(root: Path) -> dict:
    root = checked_path(root)
    if Path(_git(root, 'rev-parse', '--show-toplevel').strip()).resolve() != root:
        raise ValueError('target must be its own Git worktree')
    if _git(root, 'rev-parse', 'HEAD').strip() != PIN:
        raise ValueError('local target revision differs from the reviewed pin')
    if _git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=all'):
        raise ValueError('target worktree must be clean')
    result = {}
    for name in SOURCES + HEADERS:
        path = local_input_path(root, name)
        flags = _git(root, 'ls-files', '-v', '-z', '--', name)
        if not flags.startswith('H '):
            raise ValueError('input must be tracked without hidden index flags: ' + name)
        raw = read_bounded(path, 2 * 1024 * 1024)
        result[name] = {'bytes': len(raw), 'sha256': sha(raw)}
    if b'#define ZLIB_VERSION "1.3.1"' not in read_bounded(root / 'zlib.h', 2 * 1024 * 1024):
        raise ValueError('reviewed source version not present')
    return result


def sandbox(command: list[str], *, inputs: Path, build: Path | None = None,
            executable: Path | None = None, compile_mode: bool = False) -> list[str]:
    """No host-writable mount in execution mode; toolchain/input mounts read-only."""
    args = ['wsl.exe', '-d', 'Ubuntu', '--'] if os.name == 'nt' else []
    seconds = 60 if compile_mode else 10
    args += ['/usr/bin/timeout', '--kill-after=2s', str(seconds), '/usr/bin/bwrap',
             '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
             '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
             '--ro-bind', '/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
             '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
             '--ro-bind', '/home/airgap/llvm', '/toolchain',
             '--ro-bind', linux(inputs), '/input', '--clearenv',
             '--setenv', 'PATH', '/toolchain/bin:/usr/bin:/bin',
             '--setenv', 'HOME', '/nonexistent', '--setenv', 'LANG', 'C',
             '--setenv', 'ASAN_OPTIONS', ASAN,
             '--setenv', 'ASAN_SYMBOLIZER_PATH', '/toolchain/bin/llvm-symbolizer',
             '--setenv', 'UBSAN_OPTIONS', 'halt_on_error=1:print_stacktrace=1']
    if compile_mode:
        if build is None or executable is not None:
            raise ValueError('compile mode needs a dedicated build directory')
        args += ['--bind', linux(build), '/work', '--chdir', '/work']
    else:
        if build is not None:
            raise ValueError('runtime must not mount a writable build directory')
        if executable is not None:
            args += ['--ro-bind', linux(executable), '/case']
        args += ['--chdir', '/tmp']
    args += ['/usr/bin/prlimit', '--cpu=' + ('45' if compile_mode else '5'),
             '--fsize=' + ('33554432' if compile_mode else '1048576'),
             '--nofile=128', '--core=0']
    # ASan reserves a large virtual shadow area. Do not use RLIMIT_AS for ASan;
    # its RSS watchdog is supplementary, NOT a kernel/cgroup hard memory limit.
    if compile_mode:
        args += ['--as=4294967296']
    return args + ['--'] + command


def classify(stdout: bytes, stderr: bytes, mode: str, returncode: int | None,
             process_status: str) -> str:
    if process_status == 'timeout':
        return 'timeout'
    text = stderr.decode('utf-8', errors='replace')
    if any(marker in text for marker in SANITIZER_MARKERS):
        return 'sanitizer_report_requires_review'
    if process_status != 'completed' or type(returncode) is not int or returncode != 0:
        return 'execution_failed'
    try:
        value = decode_json(stdout)
    except ValueError:
        return 'invalid_control_output'
    expected = {'status': 'roundtrip_and_capture_passed', 'mode': mode,
                'input_bytes': 65, 'output_bytes': 8, 'counts_as_new_vulnerability': False}
    if json.dumps(value, sort_keys=True) != json.dumps(expected, sort_keys=True):
        return 'invalid_control_output'
    if 'CASE_START mode=' + mode + ' zlib=1.3.1 ' not in text or 'CASE_INVALID' in text:
        return 'invalid_control_output'
    return 'functional_control_passed'


def run(root: Path, output: Path, *, allow_target_execution: bool, approval_reference: str) -> dict:
    if allow_target_execution is not True or not approval_reference.strip():
        raise ValueError('explicit execution opt-in and approval reference required')
    if len(approval_reference) > 512 or any(ord(x) < 32 for x in approval_reference):
        raise ValueError('invalid approval reference')
    root, output = checked_path(root), checked_path(output)
    if output.exists() or not output.parent.is_dir() or output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError('use a new output directory outside the source tree')
    before = capture_source(root)
    harness = read_bounded(HARNESS, 128 * 1024)
    output.mkdir()
    inputs = output / 'inputs'; inputs.mkdir()
    for name, meta in before.items():
        data = read_bounded(root / name, 2 * 1024 * 1024)
        if sha(data) != meta['sha256']:
            raise ValueError('source changed while capturing')
        (inputs / name).write_bytes(data)
    (inputs / 'case.c').write_bytes(harness)
    artifacts, records = [], []

    def save(name: str, data: bytes) -> dict:
        with (output / name).open('xb') as stream:
            stream.write(data)
        meta = {'path': name, 'bytes': len(data), 'sha256': sha(data)}
        artifacts.append(meta)
        return meta

    def invoke(label: str, command: list[str], limit: int) -> dict:
        observed = _invoke(command, limit, output_limit=1024 * 1024)
        meta = {k: observed[k] for k in ('status', 'reason', 'returncode', 'seconds')}
        meta.update(label=label, command=command,
                    stdout=save(label + '.stdout', observed['stdout']),
                    stderr=save(label + '.stderr', observed['stderr']))
        records.append(meta)
        return observed

    probe_code = ('import os,json; s=open("/proc/self/status").read(); '
                  'print(json.dumps({"uid":os.getuid(),"home_hidden":not os.path.exists("/home/airgap"),'
                  '"host_mount_hidden":not os.path.exists("/mnt/c"),'
                  '"interfaces":[x.split(":")[0].strip() for x in open("/proc/net/dev") if ":" in x],'
                  '"effective_capabilities":[x.split()[1] for x in s.splitlines() if x.startswith("CapEff:")][0]}))')
    probe = invoke('isolation-preflight', sandbox(['/usr/bin/python3', '-c', probe_code], inputs=inputs), 15)
    isolation = decode_json(probe['stdout']) if probe['returncode'] == 0 else {}
    if not (isolation.get('home_hidden') is True and isolation.get('host_mount_hidden') is True
            and isolation.get('interfaces') == ['lo'] and isolation.get('effective_capabilities') == '0000000000000000'):
        raise ValueError('isolation preflight failed; target was not run')
    version = invoke('compiler-version', sandbox(['/toolchain/bin/clang', '--version'], inputs=inputs), 15)
    if version['status'] != 'completed' or b'clang version' not in version['stdout']:
        raise ValueError('trusted compiler version unavailable')
    runs, builds = [], []
    for iteration in (1, 2):
        folder = output / ('build-' + str(iteration)); folder.mkdir()
        argv = ['/toolchain/bin/clang', '--no-default-config', '-std=c11', '-O1', '-g',
                '-fno-omit-frame-pointer', '-fsanitize=address,undefined', '-I/input',
                '/input/case.c', *['/input/' + n for n in SOURCES], '-o', '/work/case']
        build = invoke('build-' + str(iteration), sandbox(argv, inputs=inputs, build=folder, compile_mode=True), 65)
        if build['status'] != 'completed' or not (folder / 'case').is_file():
            raise ValueError('target build failed; no runtime success recorded')
        binary = read_bounded(folder / 'case', 32 * 1024 * 1024)
        bin_meta = {'path': 'build-' + str(iteration) + '/case', 'bytes': len(binary), 'sha256': sha(binary)}
        artifacts.append(bin_meta); builds.append(bin_meta)
        selected_modes = ('fragmented', 'fragmented', *MODES) if iteration == 1 else MODES
        for number, mode in enumerate(selected_modes, 1):
            label = 'run-' + str(iteration) + '-' + str(number) + '-' + mode
            result = invoke(label, sandbox(['/case', mode], inputs=inputs, executable=folder / 'case'), 15)
            outcome = classify(result['stdout'], result['stderr'], mode, result['returncode'], result['status'])
            runs.append({'id': label, 'build': iteration, 'mode': mode, 'outcome': outcome,
                         'target_executed': b'CASE_START ' in result['stderr'],
                         'binary_sha256': bin_meta['sha256'], 'record': label})
    after = capture_source(root)
    if before != after or read_bounded(HARNESS, 128 * 1024) != harness:
        raise ValueError('original inputs changed during validation')
    for name, meta in before.items():
        if sha(read_bounded(inputs / name, 2 * 1024 * 1024)) != meta['sha256']:
            raise ValueError('captured source changed')
    if sha(read_bounded(inputs / 'case.c', 128 * 1024)) != sha(harness):
        raise ValueError('captured harness changed')
    passed = len(runs) == 10 and all(r['outcome'] == 'functional_control_passed' for r in runs)
    result = {'schema': 'authorized-zlib-controls-0.1',
              'status': 'functional_controls_passed' if passed else 'runtime_review_required',
              'approval': {'reference': approval_reference, 'origin': 'explicit_user_opt_in',
                           'scope': 'pinned_local_zlib_fixed_input_controls', 'independently_authenticated': False},
              'source_root': str(root), 'source_revision': PIN, 'source_version': '1.3.1',
              'source_files': before, 'original_inputs_unchanged': True,
              'harness_sha256': sha(harness), 'records': records, 'artifacts': artifacts,
              'builds': builds, 'runs': runs, 'isolation_preflight': isolation,
              'real_target_runs': sum(r['target_executed'] for r in runs),
              'historical_vulnerable_revision_executed': False,
              'historical_bug_reproduced': False, 'confirmed_new_vulnerabilities': 0,
              'product_reachability_verified': False, 'llm_invoked': False,
              'limitations': ['Known fixed local revision controls only, not a reproduced vulnerability.',
                  'Two builds and separate sandbox sessions are not a second-person independent review.',
                  'ASan RSS watchdog is not a cgroup hard-memory guarantee; virtual memory is unrestricted at runtime.',
                  'LeakSanitizer disabled; fixed inputs do not establish full library or product safety.']}
    exclusive_json(output / 'acceptance.json', result)
    return result


def verify(output: Path, root: Path = DEFAULT_ROOT) -> dict:
    output = checked_path(output)
    value = decode_json(read_bounded(output / 'acceptance.json', 4 * 1024 * 1024))
    if (value.get('schema') != 'authorized-zlib-controls-0.1' or value.get('source_revision') != PIN
            or value.get('source_version') != '1.3.1' or value.get('original_inputs_unchanged') is not True):
        raise ValueError('invalid runtime receipt')
    root = checked_path(root)
    if str(root) != value.get('source_root'):
        raise ValueError('receipt source differs from explicitly supplied root')
    if set(value['source_files']) != set(SOURCES + HEADERS) or capture_source(root) != value['source_files']:
        raise ValueError('original source differs from runtime receipt')
    for name, meta in value['source_files'].items():
        raw = read_bounded(local_input_path(output / 'inputs', name), 2 * 1024 * 1024)
        if len(raw) != meta['bytes'] or sha(raw) != meta['sha256']:
            raise ValueError('captured source digest mismatch')
    if sha(read_bounded(output / 'inputs/case.c', 128 * 1024)) != value['harness_sha256']:
        raise ValueError('harness digest mismatch')
    if len(value['artifacts']) != 30 or len({a['path'] for a in value['artifacts']}) != 30:
        raise ValueError('artifact set mismatch')
    artifacts = {a['path']: a for a in value['artifacts']}
    for item in value['artifacts']:
        raw = read_bounded(local_input_path(output, item['path']), 32 * 1024 * 1024)
        if len(raw) != item['bytes'] or sha(raw) != item['sha256']:
            raise ValueError('artifact digest mismatch')
    records = {r['label']: r for r in value['records']}
    if len(records) != 14 or len(value['records']) != 14 or len(value['runs']) != 10:
        raise ValueError('runtime record count mismatch')
    expected = [(i, n, m) for i in (1, 2) for n, m in enumerate(
        ('fragmented', 'fragmented', *MODES) if i == 1 else MODES, 1)]
    required_records = {'isolation-preflight', 'compiler-version', 'build-1', 'build-2'}
    required_records.update('run-' + str(i) + '-' + str(n) + '-' + m for i, n, m in expected)
    if set(records) != required_records or {b['path'] for b in value['builds']} != {'build-1/case', 'build-2/case'}:
        raise ValueError('build or run schedule mismatch')
    if len(value['builds']) != 2 or any(b != artifacts.get(b['path']) for b in value['builds']):
        raise ValueError('build metadata differs from binary artifact')
    for record in records.values():
        for stream in ('stdout', 'stderr'):
            meta = record[stream]
            if meta != artifacts.get(record['label'] + '.' + stream):
                raise ValueError('process stream not bound to artifact set')
    for index, (iteration, number, mode) in enumerate(expected):
        run = value['runs'][index]
        label = 'run-' + str(iteration) + '-' + str(number) + '-' + mode
        if run['id'] != label or run['record'] != label or run['mode'] != mode or run['build'] != iteration:
            raise ValueError('run schedule changed')
        binary = artifacts['build-' + str(iteration) + '/case']
        if run['binary_sha256'] != binary['sha256']:
            raise ValueError('run binary binding mismatch')
    for run in value['runs']:
        record = records[run['record']]
        out = read_bounded(local_input_path(output, record['stdout']['path']), 1024 * 1024)
        err = read_bounded(local_input_path(output, record['stderr']['path']), 1024 * 1024)
        if classify(out, err, run['mode'], record['returncode'], record['status']) != run['outcome']:
            raise ValueError('runtime classification differs from raw logs')
        if run['target_executed'] is not (b'CASE_START ' in err):
            raise ValueError('execution marker mismatch')
    for label in ('isolation-preflight', 'compiler-version', 'build-1', 'build-2'):
        record = records[label]
        if record['status'] != 'completed' or type(record['returncode']) is not int or record['returncode'] != 0:
            raise ValueError('successful control receipt requires completed preflight and builds')
    raw_probe = read_bounded(output / 'isolation-preflight.stdout', 1024 * 1024)
    probe = decode_json(raw_probe)
    if probe != value['isolation_preflight'] or not (probe.get('home_hidden') is True
            and probe.get('host_mount_hidden') is True and probe.get('interfaces') == ['lo']
            and probe.get('effective_capabilities') == '0000000000000000'):
        raise ValueError('isolation receipt mismatch')
    passed = all(r['outcome'] == 'functional_control_passed' for r in value['runs'])
    expected_status = 'functional_controls_passed' if passed else 'runtime_review_required'
    if (value['status'] != expected_status or type(value['real_target_runs']) is not int
            or value['real_target_runs'] != sum(r['target_executed'] for r in value['runs'])):
        raise ValueError('runtime summary differs from observations')
    if (type(value.get('confirmed_new_vulnerabilities')) is not int or value['confirmed_new_vulnerabilities'] != 0
            or value.get('historical_bug_reproduced') is not False
            or value.get('historical_vulnerable_revision_executed') is not False
            or value.get('product_reachability_verified') is not False or value.get('llm_invoked') is not False):
        raise ValueError('controls cannot be promoted to vulnerability evidence')
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-target-execution', action='store_true')
    parser.add_argument('--approval-reference', default='')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.verify and (args.allow_target_execution or args.approval_reference):
            raise ValueError('offline verification must not request execution')
        result = verify(args.output, args.root) if args.verify else run(args.root, args.output,
            allow_target_execution=args.allow_target_execution, approval_reference=args.approval_reference)
        print(json.dumps({k: result[k] for k in ('status', 'real_target_runs',
            'historical_bug_reproduced', 'confirmed_new_vulnerabilities')}, ensure_ascii=False))
        return 0 if result['status'] == 'functional_controls_passed' else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('LOCAL_CONTROL_REJECTED ' + type(exc).__name__ + ': ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
