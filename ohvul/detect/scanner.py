from __future__ import annotations
import hashlib, pathlib, re, os, stat
from datetime import datetime, timezone
from ohvul.domain.evidence import make_bundle
from ohvul.source_scope import relative_paths, local_input_path, is_link
from ohvul.detect.lexical import review_syntax, RULE_VERSION

EXTENSIONS={".c",".h",".cc",".cpp",".cxx",".hpp"}
RULES=[("CWE-190","integer-overflow-length","Possible integer arithmetic used as a memory-size argument",re.compile(r"\b(?:malloc|calloc|realloc|memcpy|memmove)\s*\([^;\n]*[+*]\s*[^;\n]*\)")),("CWE-476","null-dereference","Possible dereference of a pointer after a nullable-returning call",re.compile(r"(?:->|\*)\s*[A-Za-z_]\w*")),("CWE-122","heap-buffer-overflow","Use of a memory-copy API requires manual boundary review",re.compile(r"\b(?:strcpy|strcat|sprintf|memcpy|memmove)\s*\("))]
def _line_hash(line): return hashlib.sha256(line.strip().encode()).hexdigest()[:16]
def scan_path(root, relative_files=None):
    root = pathlib.Path(root).resolve()
    if not root.is_dir():
        raise ValueError('source root must be an existing directory')
    findings, bundles, records, errors, skipped_dirs, observations = [], [], [], [], [], []
    observation_bundles = []
    attempted = succeeded = failed = skipped = 0
    explicit = relative_files is not None
    if explicit:
        names = sorted(relative_paths(relative_files, nonempty=True))
        if any(pathlib.Path(name).suffix.lower() not in EXTENSIONS for name in names):
            raise ValueError('explicit source must have a supported C/C++ extension')
    else:
        names = []
        def enumeration_error(exc):
            errors.append({'engine': 'builtin_rule', 'status': 'input_error', 'stage': 'enumeration',
                           'source_file': str(exc.filename or root), 'error_type': type(exc).__name__,
                           'reason': str(exc)[:1024]})
        # Path.rglob can suppress directory I/O errors on some Python versions.
        # os.walk's onerror lets us retain incomplete-enumeration evidence.
        for directory, dirs, files in os.walk(root, topdown=True, onerror=enumeration_error, followlinks=False):
            retained = []
            for name in sorted(dirs):
                path = pathlib.Path(directory) / name
                if is_link(path):
                    skipped_dirs.append(path.relative_to(root).as_posix())
                else:
                    retained.append(name)
            dirs[:] = retained
            names.extend((pathlib.Path(directory) / name).relative_to(root).as_posix()
                         for name in sorted(files) if pathlib.Path(name).suffix.lower() in EXTENSIONS)
        names.sort()
    for relative in names:
        f = root / relative
        record = {'engine': 'builtin_rule', 'source_file': str(f), 'file': relative}
        try:
            if not explicit and is_link(f):
                skipped += 1
                records.append({**record, 'status': 'skipped', 'reason': 'symbolic link or junction'})
                continue
            f = local_input_path(root, relative)
            if not stat.S_ISREG(f.stat().st_mode):
                raise ValueError('source input is not a regular file')
            attempted += 1
            raw = f.read_bytes()
            lines = raw.decode('utf-8').splitlines()
        except (OSError, ValueError) as exc:
            failed += 1
            error = {**record, 'status': 'input_error', 'error_type': type(exc).__name__, 'reason': str(exc)[:1024]}
            errors.append(error)
            records.append(error)
            continue
        succeeded += 1
        digest = hashlib.sha256(raw).hexdigest()
        records.append({**record, 'status': 'completed', 'file_sha256': digest, 'bytes': len(raw)})
        syntax = review_syntax(raw.decode('utf-8'))
        for observation in syntax['observations']:
            no = observation['line']
            evidence = {'code': lines[no - 1].strip(), 'line_hash': _line_hash(lines[no - 1]),
                        'file_sha256': digest, 'rule_version': RULE_VERSION,
                        'decision': observation['decision'], 'column': observation['column'],
                        'pointer': observation['pointer'], 'final_verdict': 'undetermined'}
            bundle = make_bundle('static_scan', {'root': str(root), 'file': relative, 'line': no}, evidence=evidence)
            observation_bundles.append(bundle.to_dict())
            observations.append({'status': 'observation', 'rule': 'lexical-review-filter',
                                 'location': {'file': relative, 'line': no},
                                 'evidence': evidence, 'evidence_id': bundle.evidence_id})
        for no, line in enumerate(lines, 1):
            if no in syntax['ignored_lines']:
                continue
            code = syntax['masked_lines'][no - 1]
            for cwe, rule, desc, rx in RULES:
                matched = bool(syntax['pointer_candidates'].get(no)) if cwe == 'CWE-476' else bool(rx.search(code))
                if matched:
                    if cwe == 'CWE-476':
                        desc = 'Pointer-use syntax without a recognized local guard; nullability and reachability remain unknown'
                    evidence = {"code": line.strip(), "line_hash": _line_hash(line), 'file_sha256': digest,
                                'rule_version': RULE_VERSION, 'cwe_candidate': cwe}
                    if cwe == 'CWE-476':
                        evidence['pointer_use_columns'] = syntax['pointer_candidates'][no]
                        evidence['nullability'] = 'unknown'
                    bundle = make_bundle("static_scan", {"root": str(root), "file": relative, "line": no}, evidence=evidence)
                    bundles.append(bundle.to_dict())
                    findings.append({"alert_id": f"AL-{len(findings)+1:06d}", "source": "builtin_rule", "cwe_candidate": cwe, "rule": rule, "description": desc, "location": {"file": relative, "line": no}, "evidence": evidence, "evidence_id": bundle.evidence_id, "status": "candidate"})
    status = 'completed' if not errors else ('partial' if succeeded else 'input_error')
    scope_complete = not any(e.get('stage') == 'enumeration' for e in errors)
    return {'schema_version': '0.3', 'status': status,
            'scan': {'root': str(root), 'engine': 'builtin_rule', 'files_requested': len(names) if scope_complete else None,
                     'files_discovered': len(names),
                     'files_attempted': attempted, 'files_scanned': succeeded, 'files_failed': failed,
                     'files_skipped': skipped, 'scope_complete': scope_complete,
                     'directories_skipped': skipped_dirs, 'completed_at': datetime.now(timezone.utc).isoformat()},
            'file_results': records, 'input_errors': errors, 'findings': findings,
            'evidence_bundles': bundles + observation_bundles,
            'rule_observations': observations,
            'safety': {'local_only': True, 'no_execution': True, 'no_network': True}}







