"""Opt-in real Clang/clang-tidy integration demo on disposable synthetic sources.

Creates two local Git fixture repositories under a NEW output directory. Never
executes target code, installs tools, accesses remote repositories, or modifies
project Git. A successful demo is not an OpenHarmony vulnerability validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]


def run_demo(output: Path) -> dict:
    output = Path(output).absolute()
    for path in (output, *output.parents):
        if (path.name.casefold() == '.git' or path.is_symlink()
                or getattr(path, 'is_junction', lambda: False)()):
            raise ValueError('demo output must not use Git metadata or linked paths')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    component, dependency = source / 'component', source / 'dependency'
    component.mkdir(parents=True)
    (dependency / 'include').mkdir(parents=True)
    (component / 'unsafe.c').write_text(
        '#include "sample_value.h"\n'
        'sample_value synthetic_null(void) {\n'
        '    sample_value *value = 0;\n'
        '    return *value;\n}\n', encoding='utf-8', newline='\n')
    (component / 'safe.c').write_text(
        '#include "sample_value.h"\n'
        'sample_value synthetic_safe(sample_value *value) {\n'
        '    return value ? *value : 0;\n}\n', encoding='utf-8', newline='\n')
    (dependency / 'include/sample_value.h').write_text(
        'typedef int sample_value;\n', encoding='utf-8', newline='\n')
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    records = []
    summary = {'schema': 'synthetic-static-demo-0.1', 'status': 'failed',
               'scope': 'synthetic-fixtures-only', 'target_executed': False,
               'openharmony_verified': False, 'output': str(output), 'commands': records}

    def command(label, argv, *, expected=0):
        start = time.perf_counter()
        completed = subprocess.run([str(x) for x in argv], cwd=PROJECT, env=env,
                                   capture_output=True, text=True, encoding='utf-8',
                                   errors='replace', timeout=180, check=False)
        text = completed.stdout + completed.stderr
        log = output / (label + '.log')
        log.write_text(text, encoding='utf-8', newline='\n')
        records.append({'label': label, 'command': [str(x) for x in argv],
                        'returncode': completed.returncode, 'seconds': time.perf_counter() - start,
                        'log': log.name, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        if (completed.returncode == 0) != (expected == 0):
            raise RuntimeError(label + ' returned an unexpected exit code; inspect ' + str(log))
        return completed.stdout

    def tree_hashes():
        return {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in source.rglob('*') if p.is_file()}

    try:
        heads = {}
        for name, repo in (('component', component), ('dependency', dependency)):
            command(name + '-init', ['git', '-C', repo, 'init', '-q', '--template='])
            command(name + '-add', ['git', '-C', repo, 'add', '--', '.'])
            command(name + '-commit', ['git', '-C', repo, '-c', 'user.name=Local Fixture',
                    '-c', 'user.email=fixture@example.invalid', '-c',
                    'core.hooksPath=' + str(output / 'no-hooks'), 'commit', '-qm', 'synthetic fixture'])
            heads[name] = command(name + '-head', ['git', '-C', repo, 'rev-parse', 'HEAD']).strip()
        baseline = tree_hashes()
        template = {'schema': 'engine-profile-0.1', 'component': 'synthetic_static_demo',
                    'source_repositories': {'component': heads['component']},
                    'source_files': ['component/unsafe.c', 'component/safe.c'],
                    'include_dirs': ['dependency/include'], 'defines': [],
                    'extra_compile_args': ['-std=c11'],
                    'engines': ['clang-static-analyzer', 'clang-tidy']}
        template_path, profile_path = output / 'template.json', output / 'captured-profile.json'
        template_path.write_text(json.dumps(template, indent=2), encoding='utf-8')
        receipt = json.loads(command('capture', [sys.executable, '-m', 'ohvul.profile_capture',
                    '--template', template_path, '--source-root', source, '--output', profile_path]))
        if receipt['added_repositories'] != {'dependency': heads['dependency']}:
            raise ValueError('capture did not discover the exact dependency repository')
        result_path, report_path = output / 'result.json', output / 'report.json'
        checkpoint, journal = output / 'checkpoint.json', output / 'journal.jsonl'
        command('scan', [sys.executable, '-m', 'ohvul.cli', source,
                '--engine-profile', profile_path, '--output', result_path,
                '--checkpoint', checkpoint, '--journal', journal,
                '--report-output', report_path, '--task-id', 'synthetic-static-demo'])
        command('verify-result', [sys.executable, '-m', 'ohvul.verify', result_path])
        command('verify-report', [sys.executable, '-m', 'ohvul.report_verify', report_path, result_path])
        command('verify-journal', [sys.executable, '-m', 'ohvul.journal_status', journal,
                '--task-id', 'synthetic-static-demo', '--result', result_path,
                '--checkpoint', checkpoint, '--json'])
        result = json.loads(result_path.read_text(encoding='utf-8'))
        if not result.get('profile_validations'):
            raise ValueError('profile validation receipt was lost by main CLI merging')
        builtin = [item for item in result['findings'] if item['source'] == 'builtin_rule']
        builtin_counts = {'unsafe': sum(item['location']['file'] == 'component/unsafe.c' for item in builtin),
                          'safe': sum(item['location']['file'] == 'component/safe.c' for item in builtin)}
        if builtin_counts != {'unsafe': 1, 'safe': 0}:
            raise ValueError('builtin pointer syntax regression in synthetic controls')
        if not any(item['evidence']['decision'] == 'same_expression_guard'
                   for item in result.get('rule_observations', [])):
            raise ValueError('guard observation was lost by main CLI merging')
        counts, versions = {}, {}
        for engine in ('clang', 'clang-tidy'):
            findings = [x for x in result['findings'] if x['source'] == engine]
            counts[engine] = {'unsafe': sum(x['location']['file'] == 'component/unsafe.c' for x in findings),
                              'safe': sum(x['location']['file'] == 'component/safe.c' for x in findings)}
            observed = [x for x in result['engine_observations'] if x['engine'] == engine]
            versions[engine] = [x['engine_version'] for x in observed]
            if not observed or any(x['status'] != 'completed' or x['scan']['files_scanned'] != 2 for x in observed):
                raise ValueError(engine + ' did not successfully analyze both synthetic files')
            if counts[engine]['unsafe'] < 1 or counts[engine]['safe'] != 0:
                raise ValueError(engine + ' failed the synthetic positive/negative control')
            if any(item['cwe_candidate'] != 'CWE-476' for item in findings):
                raise ValueError(engine + ' lost the null-dereference CWE mapping')
            if 'unknown' in versions[engine]:
                raise ValueError(engine + ' version was not observed')
        bad_profile = json.loads(profile_path.read_text(encoding='utf-8'))
        bad_profile['source_repositories']['component'] = 'f' * 40
        bad_path = output / 'wrong-pin.json'
        bad_path.write_text(json.dumps(bad_profile), encoding='utf-8')
        command('reject-wrong-pin', [sys.executable, '-m', 'ohvul.cli', source,
                '--engine-profile', bad_path, '--output', output / 'failed-result.json',
                '--checkpoint', output / 'failed-checkpoint.json', '--journal', output / 'failed-journal.jsonl',
                '--report-output', output / 'failed-report.json', '--task-id', 'wrong-pin'], expected=1)
        failed = json.loads((output / 'failed-checkpoint.json').read_text(encoding='utf-8'))
        events = [json.loads(x)['event'] for x in (output / 'failed-journal.jsonl').read_text(encoding='utf-8').splitlines()]
        if (failed['state'] != 'blocked' or failed['result_sha256'] is not None
                or events != ['begin', 'abort'] or (output / 'failed-result.json').exists()
                or (output / 'failed-report.json').exists()):
            raise ValueError('wrong repository pin produced a successful artifact or binding')
        if tree_hashes() != baseline:
            raise ValueError('synthetic source repositories changed during validation')
        summary.update(status='passed', fixture_heads=heads, engine_candidates=counts,
                       builtin_candidates=builtin_counts,
                       candidate_observations=len(result['findings']),
                       known_synthetic_defects=1, confirmed_real_vulnerabilities=0,
                       engine_versions=versions, source_unchanged=True, wrong_pin_rejected=True,
                       profile_sha256=receipt['profile_sha256'],
                       result_sha256=hashlib.sha256(result_path.read_bytes()).hexdigest())
    except Exception as exc:
        summary.update(error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        (output / 'acceptance.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new directory for local synthetic fixtures and evidence')
    args = parser.parse_args()
    try:
        result = run_demo(args.output)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
