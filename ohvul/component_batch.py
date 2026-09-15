"""Explicit serial local static-analysis batches; no resume or target execution."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import time

from .engine_profile import prepare_profile, recheck_profile, _read_profile
from .engine_shards import scan_engine_profile
from .report.schema import build_audit_report, validate_report_against_result
from .source_scope import is_link
from .source_snapshot import source_snapshot
from .verify import validate_result


MAX_MANIFEST_BYTES = 1024 * 1024
DEFAULT_MAX_JOBS = 32
BOUNDARY = {'candidate_only': True, 'confirmed_vulnerabilities': 0,
            'local_only': True, 'target_executed': False, 'no_network': True}
_RESERVED = re.compile(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?')


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest field: ' + key)
        result[key] = value
    return result


def _path(value, parent):
    if (not isinstance(value, str) or not value or value != value.strip()
            or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid local path')
    win = PureWindowsPath(value)
    if (value.startswith(('\\\\', '//')) or (win.drive and not win.root)
            or (win.root and not win.drive and not value.startswith('/'))
            or (win.drive and os.name != 'nt')):
        raise ValueError('UNC, device and drive-relative paths are unsupported')
    # Reject alternate streams, reserved names and ambiguous Windows spellings
    # on every host, so manifests remain portable.
    for part in win.parts[1:] if win.anchor else win.parts:
        if (part not in ('.', '..') and (part.endswith((' ', '.'))
                or ':' in part or _RESERVED.fullmatch(part) or part.lower() == '.git')):
            raise ValueError('reserved or Git metadata path')
    path = Path(value.replace('\\', '/'))
    path = path if path.is_absolute() else parent / path
    # Inspect lexical ancestors BEFORE resolving, including ancestors preceding .. .
    for ancestor in (path, *path.parents):
        if is_link(ancestor):
            raise ValueError('symbolic links and junctions are unsupported')
    return path.resolve()


def _read_manifest(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('manifest exceeds size limit')
    return raw


def _validate(manifest, output, max_jobs, timeout, preflight_only):
    if type(max_jobs) is not int or max_jobs <= 0:
        raise ValueError('max_jobs must be a positive integer')
    if (type(timeout) is not int or not 1 <= timeout <= 900
            or type(preflight_only) is not bool):
        raise ValueError('timeout must be an integer between 1 and 900; mode must be boolean')
    manifest = _path(os.fspath(manifest), Path.cwd())
    raw = _read_manifest(manifest)
    def constant(value):
        raise ValueError('invalid JSON constant: ' + value)
    data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique, parse_constant=constant)
    if (not isinstance(data, dict) or set(data) != {'schema', 'jobs'}
            or data['schema'] != 'component-batch-0.1' or not isinstance(data['jobs'], list)
            or not 1 <= len(data['jobs']) <= max_jobs):
        raise ValueError('invalid batch schema or job count')
    ids = set()
    # Complete the structural pass before touching any job path.
    for job in data['jobs']:
        if not isinstance(job, dict) or set(job) != {'id', 'source_root', 'profile'}:
            raise ValueError('invalid job fields')
        name = job['id']
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name)
                or _RESERVED.fullmatch(name) or name.lower() in ids):
            raise ValueError('invalid or duplicate portable job id')
        ids.add(name.lower())
        if any(not isinstance(job[k], str) or not job[k] for k in ('source_root', 'profile')):
            raise ValueError('job paths must be nonempty strings')
    output = _path(os.fspath(output), Path.cwd())
    jobs, aliases, profile_inodes = [], set(), set()
    for job in data['jobs']:
        root = _path(job['source_root'], manifest.parent)
        profile = _path(job['profile'], manifest.parent)
        if not root.is_dir() or not profile.is_file():
            raise ValueError('source directory and profile file must exist')
        if profile.samefile(manifest):
            raise ValueError('manifest/profile conflict')
        alias = (os.path.normcase(str(root)), os.path.normcase(str(profile)))
        inode_alias = (root.stat().st_dev, root.stat().st_ino,
                       profile.stat().st_dev, profile.stat().st_ino)
        if alias in aliases or inode_alias in profile_inodes:
            raise ValueError('duplicate job path alias')
        aliases.add(alias)
        profile_inodes.add(inode_alias)
        if output.is_relative_to(root) or root.is_relative_to(output):
            raise ValueError('output/source collision')
        if profile.is_relative_to(output) or output == profile:
            raise ValueError('output/profile collision')
        jobs.append({'id': job['id'], 'source_root': root, 'profile': profile})
    if manifest.is_relative_to(output):
        raise ValueError('output/manifest collision')
    if output.exists() or not output.parent.is_dir():
        raise ValueError('output must be new with an existing parent')
    return manifest, raw, output, jobs


def _publish(path, value):
    """Exclusively create one artifact; a failed write may leave partial bytes.

    No check-then-rename overwrite window, including on POSIX. Final acceptance
    checks exact artifact hashes. This is not a multi-file transaction.
    """
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False) + '\n').encode('utf-8')
    _path(str(path), Path.cwd())
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': path.name, 'sha256': _hash(raw), 'bytes': len(raw)}


def _no_tree_links(root):
    # Snapshot semantics are unchanged. Reject links rather than allowing its
    # recursive reader (or an analyzer) to traverse linked source directories.
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=_raise):
        for name in dirs + files:
            if is_link(Path(directory) / name):
                raise ValueError('source tree contains a symbolic link or junction')


def _raise(error):
    raise error


def _bindings(manifest, raw, job, profile, receipt, snapshot):
    for path in (manifest, job['profile'], job['source_root']):
        _path(str(path), Path.cwd())
    if _read_manifest(manifest) != raw:
        raise ValueError('manifest changed during batch')
    recheck_profile(job['profile'], job['source_root'], profile, receipt)
    _no_tree_links(job['source_root'])
    if source_snapshot(job['source_root']) != snapshot:
        raise ValueError('source snapshot changed during batch')


def _check_result(result, job, receipt, snapshot):
    validate_result(result)
    if not isinstance(result['findings'], list) or not isinstance(result['evidence_bundles'], list):
        raise ValueError('invalid result containers')
    if any(item.get('status') != 'candidate' for item in result['findings']):
        raise ValueError('batch findings must remain candidate-only')
    scan = result['scan']
    if scan['root'] != str(job['source_root']) or scan['source_snapshot_sha256'] != snapshot:
        raise ValueError('result source binding mismatch')
    if result.get('profile_validation') != {**receipt, 'source_snapshot_sha256': snapshot}:
        raise ValueError('result profile receipt mismatch')
    observations = result.get('engine_observations', [result])
    if (not isinstance(observations, list) or not observations
            or any(x.get('status') != 'completed' or x.get('input_errors') for x in observations)
            or result.get('status') != 'completed' or result.get('input_errors')
            or any(x.get('status') != 'completed' for x in result.get('file_results', []))):
        raise ValueError('analysis did not complete')


def run_batch(manifest, output, *, preflight_only=False, max_jobs=DEFAULT_MAX_JOBS, timeout=300):
    """Return 0 only for a saved, rechecked all-ready/all-completed summary."""
    manifest, raw, output, jobs = _validate(manifest, output, max_jobs, timeout, preflight_only)
    output.mkdir()  # Exclusive, after validation of the ENTIRE manifest.
    started = time.monotonic()
    summary = {'schema': 'component-batch-summary-0.1', 'preflight_only': preflight_only,
               'status': 'running', 'manifest': str(manifest), 'manifest_sha256': _hash(raw),
               'max_jobs': max_jobs, 'timeout_seconds': timeout, 'boundary': BOUNDARY,
               'jobs': [{'id': j['id'], 'status': 'pending', 'artifacts': {}} for j in jobs]}
    revision = 0
    publication_failed = False
    accepted = []

    def publish_summary():
        nonlocal revision
        summary['elapsed_seconds'] = time.monotonic() - started
        summary['counts'] = {status: sum(j['status'] == status for j in summary['jobs'])
                             for status in sorted({j['status'] for j in summary['jobs']})}
        summary['totals'] = {
            'jobs': len(jobs),
            'analysis_attempted': sum(j.get('analysis_attempted') is True for j in summary['jobs']),
            'completed': sum(j['status'] == 'completed' for j in summary['jobs']),
            'ready': sum(j['status'] == 'ready' for j in summary['jobs']),
            'blocked': sum(j['status'] == 'blocked' for j in summary['jobs']),
            'failed': sum(j['status'].endswith('_failed') for j in summary['jobs']),
            'pending': sum(j['status'] == 'pending' for j in summary['jobs']),
        }
        summary['candidate_findings'] = sum(j.get('candidate_findings', 0) for j in summary['jobs'])
        revision += 1
        _publish(output / f'summary-{revision:04d}.json', summary)

    publish_summary()
    for job, entry in zip(jobs, summary['jobs']):
        tick = time.monotonic()
        folder = output / job['id']
        phase = 'preflight'
        receipt_data = {'schema': 'component-batch-receipt-0.1', 'boundary': BOUNDARY,
                        'manifest_sha256': _hash(raw), 'source_root': str(job['source_root']),
                        'profile': str(job['profile']), 'profile_receipts': [], 'preflight_only': preflight_only}
        try:
            folder.mkdir()
            receipt_data['profile_sha256'] = _hash(_read_profile(job['profile']))
            profile, receipt = prepare_profile(job['profile'], job['source_root'])
            receipt_data['profile_receipts'].append(receipt)
            if receipt['profile_sha256'] != receipt_data['profile_sha256']:
                raise ValueError('profile changed during preparation')
            _no_tree_links(job['source_root'])
            snapshot = source_snapshot(job['source_root'])
            receipt_data['source_snapshot_sha256'] = snapshot
            _bindings(manifest, raw, job, profile, receipt, snapshot)
            entry['inputs'] = {k: receipt_data[k] for k in
                               ('manifest_sha256', 'profile_sha256', 'source_snapshot_sha256', 'source_root', 'profile')}
            entry['selected_engines'] = profile['engines']
            if not preflight_only:
                phase = 'analysis'
                entry['analysis_attempted'] = True
                scan_tick = time.monotonic()
                result = scan_engine_profile(job['source_root'], job['profile'], timeout=timeout)
                entry['analysis_seconds'] = time.monotonic() - scan_tick
                phase = 'publication'
                entry['artifacts']['result'] = _publish(folder / 'result.json', result)
                phase = 'validation'
                if isinstance(result, dict):
                    receipt_data['profile_receipts'].extend(result.get('profile_validations', []))
                    if 'profile_validation' in result:
                        receipt_data['profile_receipts'].append(result['profile_validation'])
                    entry['engine_observations'] = result.get('engine_observations', [{
                        k: result[k] for k in ('status', 'scan', 'file_results', 'input_errors', 'engine_runs') if k in result}])
                _check_result(result, job, receipt, snapshot)
                entry['candidate_findings'] = len(result['findings'])
                report = build_audit_report(result)
                validate_report_against_result(report, result)
                phase = 'binding'
                _bindings(manifest, raw, job, profile, receipt, snapshot)
                phase = 'publication'
                entry['artifacts']['report'] = _publish(folder / 'report.candidate.json', report)
            phase = 'binding'
            _bindings(manifest, raw, job, profile, receipt, snapshot)
            entry['status'] = 'ready' if preflight_only else 'completed'
            accepted.append((job, entry, profile, receipt, snapshot))
        except Exception as exc:
            entry.update(status='blocked' if phase == 'preflight' else phase + '_failed',
                         error={'phase': phase, 'type': type(exc).__name__, 'message': str(exc)[:8192]})
        entry['elapsed_seconds'] = time.monotonic() - tick
        # Receipts describe observations. Only a final batch summary accepts a job.
        receipt_data.update(outcome=entry['status'], error=entry.get('error'),
                            elapsed_seconds=entry['elapsed_seconds'], acceptance='requires_final_summary')
        try:
            entry['artifacts']['receipt'] = _publish(folder / 'receipt.json', receipt_data)
            publish_summary()
        except Exception as exc:
            publication_failed = True
            entry.update(status='publication_failed', error={'phase': 'publication',
                         'type': type(exc).__name__, 'message': str(exc)[:8192]})
            try:
                entry['artifacts']['publication_error'] = _publish(folder / 'publication-error.json', entry['error'])
            except Exception:
                pass  # Persistent storage failure is reported by nonzero exit.

    # Earlier jobs may have changed while later jobs ran. Recheck all accepted
    # bindings and exact saved artifact bytes before final acceptance.
    for job, entry, profile, receipt, snapshot in accepted:
        if entry['status'] not in ('ready', 'completed'):
            continue
        try:
            _bindings(manifest, raw, job, profile, receipt, snapshot)
            for artifact in entry['artifacts'].values():
                path = output / job['id'] / artifact['path']
                _path(str(path), Path.cwd())
                if _hash(path.read_bytes()) != artifact['sha256']:
                    raise ValueError('published artifact changed')
        except Exception as exc:
            entry.update(status='binding_failed', error={'phase': 'binding',
                         'type': type(exc).__name__, 'message': str(exc)[:8192]})
    expected = 'ready' if preflight_only else 'completed'
    success = not publication_failed and all(j['status'] == expected for j in summary['jobs'])
    summary['status'] = expected if success else 'failed'
    try:
        publish_summary()
    except Exception as exc:
        print('Batch summary publication failed: ' + str(exc))
        return 1
    return 0 if success else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--max-jobs', type=int, default=DEFAULT_MAX_JOBS)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args(argv)
    try:
        return run_batch(args.manifest, args.output, preflight_only=args.preflight_only,
                         max_jobs=args.max_jobs, timeout=args.timeout)
    except (OSError, ValueError, TypeError) as exc:
        print('Batch rejected: ' + str(exc))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
