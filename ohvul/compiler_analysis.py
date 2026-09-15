"""Explicit Clang AST analysis using validated, fixed-version component inputs.

Runs the trusted compiler for syntax/AST extraction only, never the target
program, arbitrary compilation database commands, an LLM or a remote service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from .clang_facts import MAX_AST_BYTES, extract_compiler_facts, layout_from_macros, digest
from .clang_stream import capture_main_ast
from .engine_adapter import engine_result_to_audit_result, windows_to_wsl_path, _version_observation
from .engine_profile import prepare_profile, recheck_profile, profile_compile_args
from .review_queue import checked_path, read_bounded, decode_json, exclusive_json
from .source_scope import relative_paths, local_input_path
from .source_snapshot import source_snapshot
from .report.schema import build_audit_report, validate_report_against_result
from .verify import validate_result

ENGINE = 'wildtrace-clang-ast'
MAX_FILES = 128
STDERR_LIMIT = 256 * 1024
RAW_AST_LIMIT = 256 * 1024 * 1024
MAX_JSON_LINE = 2 * 1024 * 1024
COMPILER = '/home/airgap/llvm/bin/clang'


def _command(arguments, timeout):
    prefix = ['wsl.exe', '-d', 'Ubuntu', '--'] if os.name == 'nt' else []
    # Fixed executable and wrapper, no shell. Driver config discovery and common
    # implicit include-path injections are disabled. No command from input is run.
    return prefix + ['/usr/bin/timeout', '--kill-after=2s', str(timeout) + 's',
                     '/usr/bin/env', '-u', 'CPATH', '-u', 'C_INCLUDE_PATH',
                     '-u', 'CPLUS_INCLUDE_PATH', '-u', 'OBJC_INCLUDE_PATH',
                     '-u', 'CCC_OVERRIDE_OPTIONS', COMPILER, '--no-default-config', *arguments]


def _invoke(command, timeout, *, output_limit=MAX_AST_BYTES, compact_json=False, ast_source=None, ast_file=None):
    """Bounded pipe readers; both streams drained, with a finite process wait."""
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise ValueError('compiler timeout must be 1..120 seconds')
    if type(output_limit) is not int or not 1 <= output_limit <= MAX_AST_BYTES:
        raise ValueError('invalid compiler output limit')
    start = time.monotonic()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False)
    except OSError:
        return {'status': 'input_error', 'reason': 'compiler_start_failed', 'returncode': None,
                'stdout': b'', 'stderr': b'', 'seconds': time.monotonic()-start}
    buffers, overflow, io_error = [bytearray(), bytearray()], threading.Event(), threading.Event()
    raw_counts, raw_digests = [0,0], [hashlib.sha256(),hashlib.sha256()]
    projection = {}
    def drain(stream, index, limit):
        pending = b''
        def append(chunk):
            left = max(0, limit+1-len(buffers[index]))
            buffers[index].extend(chunk[:left])
            if len(buffers[index]) > limit:
                overflow.set()
                process.kill()
                return False
            return True
        try:
            if index==0 and ast_source is not None:
                raw,observation=capture_main_ast(stream,ast_source,ast_file,output_limit=limit,observation=projection)
                projection.update(observation)
                raw_counts[0]=observation['raw_bytes']
                append(raw)
                return
            while True:
                chunk = stream.read(16384)
                if not chunk:
                    if pending:
                        append(pending.lstrip(b' \t'))
                    break
                raw_counts[index] += len(chunk)
                raw_digests[index].update(chunk)
                if raw_counts[index] > (RAW_AST_LIMIT if index==0 and compact_json else limit):
                    overflow.set()
                    process.kill()
                    break
                if index==0 and compact_json:
                    # Clang pretty-prints heavily indented ASTs. Remove ONLY
                    # line-leading indentation, retaining every newline and all
                    # string bytes. JSON strings cannot contain literal newlines;
                    # malformed strings/numbers remain malformed after this pass.
                    parts = (pending+chunk).split(b'\n')
                    pending = parts.pop()
                    if len(pending)>MAX_JSON_LINE:
                        overflow.set(); process.kill(); break
                    if not append(b''.join(line.lstrip(b' \t')+b'\n' for line in parts)):
                        break
                elif not append(chunk):
                    break
        except (OSError, ValueError, TypeError, RecursionError):
            io_error.set()
            try: process.kill()
            except OSError: pass
        finally:
            stream.close()
    threads = [threading.Thread(target=drain, args=(process.stdout, 0, output_limit), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, 1, STDERR_LIMIT), daemon=True)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout+5)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
    status, reason = 'completed', None
    if overflow.is_set():
        status, reason = 'input_error', 'compiler_output_limit'
    elif timed_out or process.returncode in (124, 137):
        status, reason = 'timeout', 'compiler_timeout'
    elif any(t.is_alive() for t in threads) or io_error.is_set():
        status, reason = 'input_error', 'compiler_ast_capture_failed' if projection.get('capture_error') else 'compiler_pipe_failed'
    elif process.returncode != 0:
        status, reason = 'input_error', 'compiler_diagnostics_error'
    return {'status': status, 'reason': reason, 'returncode': process.returncode,
            'stdout': bytes(buffers[0]), 'stderr': bytes(buffers[1]), 'seconds': time.monotonic()-start,
            'stdout_raw_bytes': projection.get('raw_bytes',raw_counts[0]), 'stdout_raw_sha256':projection.get('raw_sha256',raw_digests[0].hexdigest()),
            'stdout_capture_mode':projection.get('projection','json_indentation_removed' if compact_json else 'verbatim'),
            'ast_projection':projection.get('statistics'),'capture_error':projection.get('capture_error')}


def _receipt(command, run):
    return {'command': command, 'status': run['status'], 'reason': run['reason'],
            'returncode': run['returncode'], 'seconds': run['seconds'],
            'stdout_bytes': len(run['stdout']), 'stderr_bytes': len(run['stderr']),
            'stdout_sha256': hashlib.sha256(run['stdout']).hexdigest(),
            'stdout_raw_bytes':run.get('stdout_raw_bytes',len(run['stdout'])),
            'stdout_raw_sha256':run.get('stdout_raw_sha256',hashlib.sha256(run['stdout']).hexdigest()),
            'stdout_capture_mode':run.get('stdout_capture_mode','verbatim'),
            'ast_projection':run.get('ast_projection'),
            'capture_error':run.get('capture_error'),
            'stderr_sha256': hashlib.sha256(run['stderr']).hexdigest(),
            'stderr_excerpt': run['stderr'][:4096].decode('utf-8', errors='replace')}


def run_compiler_profile(source_root, profile_path, *, selected_files=None, timeout=60):
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise ValueError('compiler timeout must be 1..120 seconds')
    root, profile_path = checked_path(source_root), checked_path(profile_path)
    if not root.is_dir():
        raise ValueError('source root must be a directory')
    profile, validation = prepare_profile(profile_path, root, selected_files=selected_files)
    files = relative_paths(profile['source_files'] if selected_files is None else selected_files, nonempty=True)
    if len(files) > MAX_FILES:
        raise ValueError('explicit compiler batch exceeds 128 files')
    snapshot = source_snapshot(root)
    args = list(profile_compile_args(profile, root))
    # The current profile contract has no target/ABI/layout-changing flags. Once
    # added, they must also be applied to the layout probe before accepting sizes.
    vcmd = _command(['--version'], 10)
    vr = _invoke(vcmd, 10, output_limit=32768)
    version = _version_observation(vr['stdout'].decode('utf-8', errors='replace'), 'compiler_command')
    lcmd = _command(['-dM', '-E', '-x', 'c', '-'], 10)
    lr = _invoke(lcmd, 10, output_limit=256*1024)
    layout = None
    if vr['status'] == lr['status'] == 'completed':
        try:
            layout = layout_from_macros(lr['stdout'].decode('utf-8'))
        except (ValueError, UnicodeError):
            pass
    results, units, findings, errors = [], [], [], []
    attempted = 0
    for name in files:
        record = {'source_file': str(local_input_path(root, name)), 'relative_file': name,
                  'engine': ENGINE, 'status': 'not_run'}
        if layout is None:
            record.update(reason='compiler_identity_or_layout_unavailable')
            results.append(record)
            errors.append({'file': name, 'reason': record['reason']})
            continue
        path = local_input_path(root, name)
        try:
            raw = read_bounded(path, 2*1024*1024)
            raw.decode('utf-8-sig')
            compiler_file = windows_to_wsl_path(path) if os.name == 'nt' else str(path)
            cmd = _command(['-fsyntax-only', '-Xclang', '-ast-dump=json', *args, compiler_file], timeout)
            attempted += 1
            run = _invoke(cmd, timeout, ast_source=raw, ast_file=compiler_file)
            record.update(status=run['status'], execution=_receipt(cmd, run),
                          source_sha256=hashlib.sha256(raw).hexdigest())
            if run['status'] != 'completed':
                raise ValueError(run['reason'])
            ast = decode_json(run['stdout'])
            facts = extract_compiler_facts(ast, raw, source_file=name, compiler_file=compiler_file, layout=layout)
            if read_bounded(path, 2*1024*1024) != raw:
                raise ValueError('source_changed_during_compilation')
            record.update(status='completed', functions=len(facts['functions']), calls=len(facts['calls']),
                          candidates=len(facts['findings']), facts_sha256=facts['facts_sha256'])
            units.append(facts)
            for finding in facts['findings']:
                finding = {**finding, 'engine_version': '1', 'evidence': {**finding['evidence'],
                    'compiler_version': version['version'], 'compiler_execution': record['execution'],
                    'profile_sha256': validation['profile_sha256'], 'facts_sha256': facts['facts_sha256'],
                    'target_layout': layout}}
                findings.append(finding)
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            if record['status'] != 'timeout':
                record['status'] = 'input_error'
            record['reason'] = type(exc).__name__ + ': ' + str(exc)[:512]
            errors.append({'file': name, 'reason': record['reason']})
        results.append(record)
    bound = True
    try:
        recheck_profile(profile_path, root, profile, validation)
        if source_snapshot(root) != snapshot:
            raise ValueError('source snapshot changed')
    except (OSError, ValueError, TypeError) as exc:
        bound = False
        errors.append({'reason': 'input_binding_changed', 'detail': type(exc).__name__})
    successful = sum(r['status'] == 'completed' for r in results)
    status = ('completed' if not errors else 'partial' if successful else 'input_error') if bound else 'input_error'
    result = engine_result_to_audit_result({'source_root': str(root), 'engine': ENGINE, 'engine_version': '1',
        'status': status, 'findings': findings, 'file_results': results, 'engine_runs': attempted,
        'files_requested': len(files), 'files_attempted': attempted, 'files_scanned': successful,
        'files_failed': len(files)-successful, 'files_skipped': 0, 'input_errors': errors},
        source_root=root, source_snapshot_sha256=snapshot)
    result.update(compiler_facts=units, compiler_profile_validation=validation, input_bindings_valid=bound,
        compiler_version=version, compiler_probes={'version': _receipt(vcmd, vr), 'layout': _receipt(lcmd, lr)},
        analysis_scope={'main_file_bodies_only': True, 'compiler_ast_parsed': successful,
                        'profile_used_for': 'compile_arguments_not_selected_engine_execution',
                        'control_flow_verified': False, 'platform_impact_verified': False,
                        'confirmed_vulnerabilities': 0})
    validate_result(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--file', action='append', dest='files')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--output', type=Path, required=True, help='new output directory outside source tree')
    args = parser.parse_args(argv)
    try:
        output, root = checked_path(args.output), checked_path(args.root)
        if output.exists() or not output.parent.is_dir() or output.is_relative_to(root) or root.is_relative_to(output):
            raise ValueError('output must be new and outside the source tree')
        result = run_compiler_profile(root, args.profile, selected_files=args.files, timeout=args.timeout)
        report = None
        if result['status'] == 'completed':
            report = build_audit_report(result)
            validate_report_against_result(report, result)
        if (source_snapshot(root) != result['scan']['source_snapshot_sha256'] or
                hashlib.sha256(read_bounded(args.profile,1024*1024)).hexdigest() !=
                result['compiler_profile_validation']['profile_sha256']):
            raise ValueError('compiler input changed before publication')
        output.mkdir()
        exclusive_json(output/'result.json', result)
        if report is not None:
            exclusive_json(output/'report.candidate.json', report)
        print(json.dumps({'status': result['status'], 'files_scanned': result['scan']['files_scanned'],
                          'candidates': len(result['findings']), 'confirmed_vulnerabilities': 0}))
        return 0 if result['status'] == 'completed' else 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('COMPILER_ANALYSIS_REJECTED ' + type(exc).__name__)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
