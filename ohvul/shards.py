"""Deterministic local source shard manifests; does not read source contents."""
from pathlib import Path
import hashlib

EXTENSIONS = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}

def scan_shard(root, shard):
    """Scan only paths from one validated manifest shard."""
    from .detect.scanner import scan_path
    files = shard.get('files') if isinstance(shard, dict) else None
    if not isinstance(files, list) or any(not isinstance(p, str) for p in files):
        raise ValueError('invalid shard')
    return scan_path(root, relative_files=files)

def scan_manifest(root, manifest, max_shards=10000):
    if not isinstance(manifest, dict) or manifest.get('root') != str(Path(root).resolve()): raise ValueError('manifest root mismatch')
    shards = manifest.get('shards')
    if not isinstance(shards, list) or len(shards) > max_shards: raise ValueError('manifest exceeds max_shards')
    return merge_shard_results([scan_shard(root, shard) for shard in shards], root, max_shards=max_shards)

def merge_shard_results(results, root, max_shards=10000):
    """Deterministically merge shard scan results without changing findings."""
    root = str(Path(root).resolve())
    if max_shards < 1 or len(results) > max_shards: raise ValueError('shard merge exceeds max_shards')
    findings = []
    bundles = []
    seen = set()
    for result in results:
        if result.get('scan', {}).get('root') != root:
            raise ValueError('shard root mismatch')
        for bundle in result.get('evidence_bundles', []):
            if bundle['evidence_id'] in seen:
                existing = next(x for x in bundles if x['evidence_id'] == bundle['evidence_id'])
                if existing != bundle: raise ValueError('conflicting shard evidence')
            else:
                seen.add(bundle['evidence_id']); bundles.append(bundle)
        findings.extend(dict(item) for item in result.get('findings', []))
    findings.sort(key=lambda f: (f['location']['file'], f['location']['line'], f['cwe_candidate']))
    for index, finding in enumerate(findings, 1):
        finding['alert_id'] = f'AL-{index:06d}'
    scan = {'root': root, 'engine': 'builtin_rule'}
    for field in ('files_requested', 'files_discovered', 'files_attempted', 'files_scanned', 'files_failed', 'files_skipped'):
        values = [r['scan'].get(field) for r in results]
        scan[field] = sum(values) if all(type(value) is int and value >= 0 for value in values) else None
    errors = [error for r in results for error in r.get('input_errors', [])]
    records = [record for r in results for record in r.get('file_results', [])]
    scan['scope_complete'] = all(r['scan'].get('scope_complete') is True for r in results)
    scan['directories_skipped'] = [p for r in results for p in r['scan'].get('directories_skipped', [])]
    if errors:
        status = 'partial' if scan['files_scanned'] else 'input_error'
    else:
        status = 'completed' if all(r.get('status') == 'completed' for r in results) else 'unknown'
    return {'schema_version': '0.3', 'status': status, 'scan': scan, 'input_errors': errors,
            'file_results': records, 'findings': findings, 'evidence_bundles': bundles,
            'rule_observations': [item for r in results for item in r.get('rule_observations', [])],
            'safety': {'local_only': True, 'no_execution': True, 'no_network': True}}

def build_manifest(root, shard_size=1000, max_files=1000000):
    root = Path(root).resolve()
    if shard_size < 1:
        raise ValueError('shard_size must be positive')
    if max_files < 1:
        raise ValueError('max_files must be positive')
    paths = sorted((p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in EXTENSIONS),
                   key=lambda p: p.relative_to(root).as_posix())
    if len(paths) > max_files:
        raise ValueError(f'source exceeds max_files={max_files}')
    shards = []
    for start in range(0, len(paths), shard_size):
        names = [p.relative_to(root).as_posix() for p in paths[start:start + shard_size]]
        digest = hashlib.sha256('\n'.join(names).encode()).hexdigest()
        shards.append({'index': len(shards), 'files': names, 'path_list_sha256': digest})
    return {'schema': '0.1', 'root': str(root), 'files': len(paths), 'shard_size': shard_size,
            'shards': shards, 'disclaimer': 'Manifest only; no source contents read or executed.'}
