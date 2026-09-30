"""Run the reviewed memcpy_s controls against a pinned local securec copy.

Opt-in only. Reuses the existing no-network sandbox, never upstream build
scripts or shell commands. These are functional controls, NOT exploit PoCs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
from ohvul.compiler_analysis import _invoke
from ohvul.engine_profile import _git
from ohvul.review_queue import checked_path, read_bounded, decode_json, exclusive_json, canonical_bytes
from ohvul.source_scope import local_input_path
from tools.validation_cases.run_zlib_controls import sandbox, SANITIZER_MARKERS

PIN = '2ae82839ecaaa7d031e66ccbd2076d671acfd615'
DEFAULT_ROOT = Path('C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function')
HARNESS = PROJECT / 'tools/validation_cases/securec_memcpy_controls.c'
INPUTS = ('src/memcpy_s.c', 'src/securecutil.h', 'include/securec.h', 'include/securectype.h')
CASES = ('bounded-copy', 'reject-count-and-reset', 'reject-null-source-and-reset',
         'reject-null-destination', 'implementation-overlap-reset', 'zero-count-no-copy')
VARIANTS = ('o0', 'o2')
REPEATS = 3
LIMIT = 1024 * 1024
PROBE = ('import os,json; s=open("/proc/self/status").read(); '
         'print(json.dumps({"home_hidden":not os.path.exists("/home/airgap"),'
         '"host_mount_hidden":not os.path.exists("/mnt/c"),'
         '"interfaces":[x.split(":")[0].strip() for x in open("/proc/net/dev") if ":" in x],'
         '"effective_capabilities":[x.split()[1] for x in s.splitlines() if x.startswith("CapEff:")][0]}))')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_inputs(root):
    root = checked_path(root)
    require(Path(_git(root, 'rev-parse', '--show-toplevel').strip()).resolve() == root,
            'target must be its own Git worktree')
    require(_git(root, 'rev-parse', 'HEAD').strip() == PIN, 'unreviewed target revision')
    require(not _git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=all'),
            'target must be clean')
    records = {}
    for name in INPUTS:
        require(_git(root, 'ls-files', '-v', '-z', '--', name).startswith('H '),
                'target input must be tracked without hidden index flags')
        raw = read_bounded(local_input_path(root, name), 2 * LIMIT)
        records[name] = {'bytes': len(raw), 'sha256': sha(raw)}
    return records


def isolate_ok(raw):
    value = decode_json(raw)
    require(isinstance(value, dict) and value.get('home_hidden') is True and value.get('host_mount_hidden') is True
            and value.get('interfaces') == ['lo']
            and value.get('effective_capabilities') == '0000000000000000',
            'required no-network isolation was not established')
    return value


def classify(stdout, stderr, returncode, status):
    text = stderr.decode('utf-8', errors='replace')
    if status == 'timeout':
        return 'timeout'
    if any(marker in text for marker in SANITIZER_MARKERS):
        return 'sanitizer_report_requires_review'
    if status != 'completed' or type(returncode) is not int or returncode != 0:
        return 'execution_failed'
    try:
        rows = [decode_json(line) for line in stdout.splitlines() if line.strip()]
    except (ValueError, UnicodeError):
        return 'invalid_control_output'
    expected = [{'case_id': c, 'kind': 'functional_control', 'passed': True,
                 'counts_as_vulnerability': False} for c in CASES]
    expected += [{'kind': 'functional_control_summary', 'cases': len(CASES),
                  'failures': 0, 'confirmed_vulnerabilities': 0}]
    if (canonical_bytes(rows) != canonical_bytes(expected)
            or text.count('CASE_START securec-memcpy-controls cases=6') != 1):
        return 'invalid_control_output'
    return 'functional_control_passed'


def steps(output):
    inputs = output / 'inputs'
    yield 'isolation', sandbox(['/usr/bin/python3', '-c', PROBE], inputs=inputs), 15
    yield 'compiler-version', sandbox(['/toolchain/bin/clang', '--version'], inputs=inputs), 15
    for variant in VARIANTS:
        folder = output / ('build-' + variant)
        command = ['/toolchain/bin/clang', '--no-default-config', '-std=c11',
                   '-O0' if variant == 'o0' else '-O2', '-g', '-fno-omit-frame-pointer',
                   '-fsanitize=address,undefined', '-DSECUREC_WITH_PERFORMANCE_ADDONS=0',
                   '-I/input/include', '-I/input/src', '/input/case.c',
                   '/input/src/memcpy_s.c', '-o', '/work/case']
        yield 'build-' + variant, sandbox(command, inputs=inputs, build=folder, compile_mode=True), 65
        for repetition in range(1, REPEATS + 1):
            yield 'run-' + variant + '-' + str(repetition), sandbox(
                ['/case'], inputs=inputs, executable=folder / 'case'), 15


def run(root, output, *, allow_target_execution=False, approval_reference=''):
    require(allow_target_execution is True and isinstance(approval_reference, str)
            and 0 < len(approval_reference.strip()) <= 512
            and all(ord(c) >= 32 for c in approval_reference), 'explicit local execution opt-in required')
    root, output = checked_path(root), checked_path(output)
    require(not output.exists() and output.parent.is_dir()
            and not output.is_relative_to(root) and not root.is_relative_to(output),
            'new output directory outside the target required')
    before = source_inputs(root)
    harness = read_bounded(HARNESS, 128 * 1024)
    output.mkdir()
    inputs = output / 'inputs'; inputs.mkdir()
    for name, meta in before.items():
        raw = read_bounded(local_input_path(root, name), 2 * LIMIT)
        require(sha(raw) == meta['sha256'], 'source changed while copying')
        dest = inputs / name; dest.parent.mkdir(exist_ok=True)
        dest.write_bytes(raw)
    (inputs / 'case.c').write_bytes(harness)
    records, artifacts, runs = [], [], []

    def save(name, raw):
        with (output / name).open('xb') as stream:
            stream.write(raw)
        meta = {'path': name, 'sha256': sha(raw), 'bytes': len(raw)}
        artifacts.append(meta)
        return meta

    isolation = None
    for label, command, timeout in steps(output):
        if label.startswith('build-'):
            (output / label).mkdir()
        observed = _invoke(command, timeout, output_limit=LIMIT)
        record = {k: observed[k] for k in ('status', 'reason', 'returncode', 'seconds')}
        record.update(label=label, command=command,
                      stdout=save(label + '.stdout', observed['stdout']),
                      stderr=save(label + '.stderr', observed['stderr']))
        records.append(record)
        # A blocked build/probe leaves its real logs, but never a success receipt.
        if not label.startswith('run-'):
            require(record['status'] == 'completed' and type(record['returncode']) is int
                    and record['returncode'] == 0, 'preflight or build failed: ' + label)
        if label == 'isolation':
            isolation = isolate_ok(observed['stdout'])
        elif label == 'compiler-version':
            require(b'clang version' in observed['stdout'], 'compiler identity unavailable')
        elif label.startswith('build-'):
            raw = read_bounded(output / label / 'case', 32 * LIMIT)
            artifacts.append({'path': label + '/case', 'bytes': len(raw), 'sha256': sha(raw)})
        else:
            variant = label.split('-')[1]
            binary = next(a for a in artifacts if a['path'] == 'build-' + variant + '/case')
            runs.append({'id': label, 'variant': variant, 'binary_sha256': binary['sha256'],
                         'entry_observed': b'CASE_START securec-memcpy-controls cases=6' in observed['stderr'],
                         'outcome': classify(observed['stdout'], observed['stderr'],
                                             observed['returncode'], observed['status'])})
    require(source_inputs(root) == before and read_bounded(HARNESS, 128 * 1024) == harness,
            'original target or harness changed')
    for name, meta in before.items():
        require(sha(read_bounded(inputs / name, 2 * LIMIT)) == meta['sha256'], 'copied input changed')
    require((inputs / 'case.c').read_bytes() == harness, 'copied harness changed')
    passed = all(r['outcome'] == 'functional_control_passed' for r in runs)
    value = {'schema': 'authorized-securec-controls-0.1', 'source_root': str(root), 'source_revision': PIN,
             'source_files': before, 'original_inputs_unchanged': True, 'harness_sha256': sha(harness),
             'approval': {'reference': approval_reference, 'origin': 'explicit_user_opt_in',
                          'scope': 'pinned_local_securec_fixed_controls', 'independently_authenticated': False},
             'isolation_preflight': isolation, 'variants': list(VARIANTS), 'repeats_per_variant': REPEATS,
             'records': records, 'artifacts': artifacts, 'runs': runs,
             'status': 'functional_controls_passed' if passed else 'runtime_review_required',
             'real_target_runs': sum(r['entry_observed'] for r in runs),
             'control_observations': len(CASES) * sum(r['outcome'] == 'functional_control_passed' for r in runs),
             'confirmed_vulnerabilities': 0, 'vulnerability_reproduced': False,
             'product_reachability_verified': False, 'llm_invoked': False,
             'limitations': ['Functional fixed-input controls, not a vulnerability PoC or whole-library safety proof.',
                 'O0/O2 with performance addons disabled are explicit host test configurations, not all products.',
                 'Overlap is an observation of this pinned implementation, not a portable API guarantee.',
                 'Independent sandbox sessions are not second-person reproduction.',
                 'ASan RSS watchdog is supplementary, not a kernel-enforced memory cap; leak checking is disabled.']}
    exclusive_json(output / 'acceptance.json', value)
    return value


def verify(output, root=DEFAULT_ROOT):
    output, root = checked_path(output), checked_path(root)
    receipt_path = output / 'acceptance.json'
    original = read_bounded(receipt_path, 4 * LIMIT)
    v = decode_json(original)
    require(isinstance(v, dict) and v.get('schema') == 'authorized-securec-controls-0.1'
            and v.get('source_root') == str(root) and v.get('source_revision') == PIN
            and v.get('original_inputs_unchanged') is True, 'invalid source receipt')
    approval = v.get('approval')
    require(isinstance(approval, dict) and set(approval) ==
            {'reference', 'origin', 'scope', 'independently_authenticated'}
            and isinstance(approval['reference'], str) and 0 < len(approval['reference'].strip()) <= 512
            and all(ord(c) >= 32 for c in approval['reference'])
            and approval['origin'] == 'explicit_user_opt_in'
            and approval['scope'] == 'pinned_local_securec_fixed_controls'
            and approval['independently_authenticated'] is False, 'invalid declared authorization scope')
    require(source_inputs(root) == v['source_files'], 'source revision/bytes changed')
    for name, meta in v['source_files'].items():
        raw = read_bounded(local_input_path(output / 'inputs', name), 2 * LIMIT)
        require(len(raw) == meta['bytes'] and sha(raw) == meta['sha256'], 'copied source mismatch')
    harness = read_bounded(output / 'inputs/case.c', 128 * 1024)
    require(sha(harness) == v['harness_sha256'] and harness == read_bounded(HARNESS, 128 * 1024),
            'harness differs from reviewed controls')
    expected = list(steps(output))
    require(len(v['records']) == len(expected), 'record count mismatch')
    artifacts = v['artifacts']; records = v['records']
    expected_paths = {label + '.' + stream for label, _, _ in expected for stream in ('stdout', 'stderr')}
    expected_paths.update('build-' + variant + '/case' for variant in VARIANTS)
    require(len(artifacts) == len(expected_paths) and {a['path'] for a in artifacts} == expected_paths,
            'artifact set mismatch')
    table = {a['path']: a for a in artifacts}
    captured = []
    def read_artifact(name):
        meta = table[name]
        require(set(meta) == {'path', 'bytes', 'sha256'} and type(meta['bytes']) is int, 'invalid artifact')
        raw = read_bounded(local_input_path(output, name), 32 * LIMIT if name.endswith('/case') else LIMIT)
        require(len(raw) == meta['bytes'] and sha(raw) == meta['sha256'], 'artifact bytes mismatch')
        captured.append((name, raw))
        return raw
    for name in sorted(expected_paths):
        read_artifact(name)
    observations = []
    for record, (label, command, _) in zip(records, expected):
        require(record['label'] == label and record['command'] == command, 'execution schedule/command differs')
        for stream in ('stdout', 'stderr'):
            require(record[stream] == table[label + '.' + stream], 'stream binding mismatch')
        out, err = read_artifact(label + '.stdout'), read_artifact(label + '.stderr')
        if label.startswith('run-'):
            variant = label.split('-')[1]
            observations.append({'id': label, 'variant': variant,
                'binary_sha256': table['build-' + variant + '/case']['sha256'],
                'entry_observed': b'CASE_START securec-memcpy-controls cases=6' in err,
                'outcome': classify(out, err, record['returncode'], record['status'])})
        else:
            require(record['status'] == 'completed' and type(record['returncode']) is int
                    and record['returncode'] == 0, 'preflight/build did not complete')
            if label == 'isolation':
                require(isolate_ok(out) == v['isolation_preflight'], 'isolation claim differs from log')
            elif label == 'compiler-version':
                require(b'clang version' in out, 'compiler identity absent')
    passed = all(r['outcome'] == 'functional_control_passed' for r in observations)
    require(canonical_bytes(observations) == canonical_bytes(v['runs']), 'run claims differ from logs')
    require(v['variants'] == list(VARIANTS) and type(v['repeats_per_variant']) is int
            and v['repeats_per_variant'] == REPEATS, 'configuration schedule mismatch')
    require(type(v['real_target_runs']) is int and v['real_target_runs'] == sum(r['entry_observed'] for r in observations)
            and type(v['control_observations']) is int and v['control_observations'] == len(CASES) *
            sum(r['outcome'] == 'functional_control_passed' for r in observations), 'summary count mismatch')
    require(v['status'] == ('functional_controls_passed' if passed else 'runtime_review_required'), 'invalid summary')
    require(type(v['confirmed_vulnerabilities']) is int and v['confirmed_vulnerabilities'] == 0
            and v['vulnerability_reproduced'] is False and v['product_reachability_verified'] is False
            and v['llm_invoked'] is False, 'controls cannot be promoted to vulnerability evidence')
    for name, raw in captured:
        require(read_bounded(output / name, 32 * LIMIT) == raw, 'artifact changed during verification')
    require(source_inputs(root) == v['source_files'], 'original source changed during verification')
    for name, meta in v['source_files'].items():
        require(sha(read_bounded(output / 'inputs' / name, 2 * LIMIT)) == meta['sha256'],
                'copied source changed during verification')
    require(read_bounded(output / 'inputs/case.c', 128 * 1024) == harness
            and read_bounded(HARNESS, 128 * 1024) == harness, 'harness changed during verification')
    require(read_bounded(receipt_path, 4 * LIMIT) == original, 'receipt changed during verification')
    return v


def attach_case(output, root, case_path, result_path, report_path, review_output):
    """Attach verified controls to an existing candidate, never a trigger claim."""
    from ohvul.runtime_evidence import _case
    output, root, case_path = checked_path(output), checked_path(root), checked_path(case_path)
    runtime = verify(output, root)
    case_raw = read_bounded(case_path, 16 * LIMIT)
    case = decode_json(case_raw)
    expected, captured, recheck_case = _case(result_path, report_path, root, case['candidate']['alert_id'])
    require(canonical_bytes(case) == canonical_bytes(expected), 'static case differs from original evidence')
    location = case['candidate']['location']
    require(location['file'] == 'src/memcpy_s.c' and location['line'] == 518,
            'controls are scoped to the reviewed memcpy_s call, not arbitrary findings')
    require(case['input_bindings']['source_file_sha256'] == runtime['source_files']['src/memcpy_s.c']['sha256'],
            'static case and executed source do not match')
    runtime_raw = read_bounded(output / 'acceptance.json', 4 * LIMIT)
    value = {'schema': 'securec-candidate-control-review-0.1', 'case_id': case['case_id'],
             'alert_id': case['candidate']['alert_id'], 'location': location,
             'input_bindings': {**case['input_bindings'], 'case_sha256': sha(case_raw),
                                'runtime_receipt_sha256': sha(runtime_raw)},
             'source_revision': PIN, 'runtime_status': runtime['status'],
             'real_target_runs': runtime['real_target_runs'], 'control_observations': runtime['control_observations'],
             'evidence_level': 'functional_negative_controls_only',
             'review_conclusion': ('The tested gates behave as expected; the internal API advisory alone remains insufficient.'
                                   if runtime['status'] == 'functional_controls_passed'
                                   else 'Control failures require investigation; no vulnerability verdict is inferred.'),
             'open_questions': ['Actual caller allocation versus destMax', 'External input control and reachable product path',
                                'Security impact beyond API misuse', 'A reproducible defect and effective repair'],
             'candidate_closed': False, 'vulnerability_reproduced': False, 'confirmed_vulnerabilities': 0,
             'final_verdict': 'undetermined', 'execution_invoked_by_attachment': False}
    def recheck():
        recheck_case()
        verify(output, root)
        require(read_bounded(case_path, 16 * LIMIT) == case_raw
                and read_bounded(output / 'acceptance.json', 4 * LIMIT) == runtime_raw, 'inputs changed before attachment')
    exclusive_json(review_output, value, forbidden_trees=[root, output],
                   input_paths=[case_path, result_path, report_path], before_publish=recheck)
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--allow-target-execution', action='store_true')
    p.add_argument('--approval-reference', default='')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--verify', action='store_true')
    mode.add_argument('--attach-case', type=Path, help='offline: bind existing controls to this verified static case')
    p.add_argument('--static-result', type=Path)
    p.add_argument('--static-report', type=Path)
    p.add_argument('--review-output', type=Path)
    a = p.parse_args(argv)
    try:
        require(not (a.verify or a.attach_case) or not (a.allow_target_execution or a.approval_reference),
                'offline verification must not request execution')
        extras = (a.static_result, a.static_report, a.review_output)
        if a.attach_case:
            require(all(extras), 'attachment requires static result, report and a new review output')
            value = attach_case(a.output, a.root, a.attach_case, a.static_result, a.static_report, a.review_output)
            print('CONTROL_REVIEW_ATTACHED functional_negative_controls_only; confirmed_vulnerabilities=0')
            return 0 if value['runtime_status'] == 'functional_controls_passed' else 1
        require(not any(extras), 'static inputs are only valid with --attach-case')
        value = verify(a.output, a.root) if a.verify else run(a.root, a.output,
            allow_target_execution=a.allow_target_execution, approval_reference=a.approval_reference)
        print(json.dumps({k: value[k] for k in ('status', 'real_target_runs', 'control_observations',
                                               'confirmed_vulnerabilities')}, ensure_ascii=False))
        return 0 if value['status'] == 'functional_controls_passed' else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('SECUREC_CONTROL_REJECTED ' + type(exc).__name__ + ': ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
