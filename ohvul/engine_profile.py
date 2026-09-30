"""Validated component analysis profiles for local engine runs."""
from __future__ import annotations
import json
import re
import subprocess
import hashlib
import os
from pathlib import Path
from .engine_adapter import windows_to_wsl_path
from .source_scope import relative_path, relative_paths, local_input_path

_PROFILE_ENGINES = {"clang-static-analyzer", "clang-tidy", "semgrep"}
_MAX_PROFILE_BYTES = 1024 * 1024
_REQUIRED = {"schema", "component", "source_repositories", "source_files", "include_dirs", "defines", "extra_compile_args", "engines"}
_OPTIONAL = {"source_root_label", "status", "disclaimer", "semgrep_rule_files", "semgrep_rule_sha256"}


def _strings(value, name, *, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value) or len(value) > 100000:
        raise ValueError(f'{name} must be an explicit list')
    if any(not isinstance(x, str) or not x.strip() or len(x) > 4096
           or any(ord(c) < 32 or ord(c) == 127 for c in x) for x in value):
        raise ValueError(f'{name} must contain nonempty strings without control characters')
    if len(set(value)) != len(value):
        raise ValueError(f'{name} contains duplicates')
    return value


def _repositories(value):
    if not isinstance(value, dict) or not value:
        raise ValueError('source_repositories must declare at least one repository')
    names = relative_paths(list(value), allow_root=True, nonempty=True)
    if any(not isinstance(commit, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', commit)
           for commit in value.values()):
        raise ValueError('source repository commits must be full SHA-1 values')
    return dict(zip(names, (x.lower() for x in value.values())))


def validate_profile(data):
    if (not isinstance(data, dict) or not _REQUIRED.issubset(data)
            or set(data) - _REQUIRED - _OPTIONAL or data.get('schema') != 'engine-profile-0.1'):
        raise ValueError('invalid engine profile fields or schema')
    for name in ('component', 'source_root_label', 'status', 'disclaimer'):
        if name in data:
            _strings([data[name]], name, nonempty=True)
    result = dict(data)
    result['source_repositories'] = _repositories(data['source_repositories'])
    for field in ('source_files', 'include_dirs', 'defines', 'extra_compile_args', 'engines', 'semgrep_rule_files'):
        value = _strings(data.get(field, []), field, nonempty=field in ('source_files', 'engines'))
        result[field] = list(value)
    for field in ('source_files', 'include_dirs', 'semgrep_rule_files'):
        result[field] = relative_paths(result[field], allow_root=field == 'include_dirs', nonempty=field == 'source_files')
    if any(engine not in _PROFILE_ENGINES for engine in result['engines']):
        raise ValueError('profile contains unsupported engine')
    if 'semgrep' in result['engines'] and not result['semgrep_rule_files']:
        raise ValueError('selected Semgrep requires explicit local rule files')
    macro_names = []
    for define in result['defines']:
        if not re.fullmatch(r'[A-Za-z_]\w*(?:=[^\r\n\x00]*)?', define, flags=re.ASCII):
            raise ValueError('invalid profile macro definition')
        macro_names.append(define.split('=', 1)[0])
    if len(set(macro_names)) != len(macro_names):
        raise ValueError('duplicate macro definitions')
    # Deliberately small reviewed subset. Include paths/defines use typed fields;
    # response files, plugins, arbitrary driver forwarding and output flags fail closed.
    fixed = {'-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread', '-fno-exceptions', '-fno-rtti',
             '-fno-common', '-fno-strict-aliasing', '-O2'}
    for argument in result['extra_compile_args']:
        if (argument not in fixed and not re.fullmatch(r'-Wno-[A-Za-z0-9_+\-]+', argument)
                and not re.fullmatch(r'-std=(?:c|gnu)(?:89|90|99|11|17|18|2x|23)|-std=(?:c\+\+|gnu\+\+)(?:98|03|11|14|17|20|2a|23|2b|26|2c)', argument)):
            raise ValueError('unsupported profile compile argument: ' + argument)
    hashes = result.get('semgrep_rule_sha256')
    if hashes is not None:
        if not isinstance(hashes, dict) or set(hashes) != set(result['semgrep_rule_files']):
            raise ValueError('rule hash keys must exactly match rule files')
        if any(not isinstance(x, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', x) for x in hashes.values()):
            raise ValueError('invalid rule SHA-256')
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate profile JSON field: ' + key)
        result[key] = value
    return result


def _read_profile(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('profile must not be a symbolic link')
    with path.open('rb') as stream:
        raw = stream.read(_MAX_PROFILE_BYTES + 1)
    if len(raw) > _MAX_PROFILE_BYTES:
        raise ValueError('profile exceeds size limit')
    return raw


def _decode_profile(raw):
    def invalid_constant(value):
        raise ValueError('invalid profile JSON constant: ' + value)
    return validate_profile(json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_object,
                                       parse_constant=invalid_constant))


def load_profile(path: Path) -> dict:
    return _decode_profile(_read_profile(path))


def profile_compile_args(profile: dict, source_root: Path) -> tuple[str, ...]:
    if not isinstance(profile, dict) or not Path(source_root).is_dir():
        raise ValueError("profile and source root are required")
    root = Path(source_root).resolve()
    profile = validate_profile(profile)
    args = ["-D" + value for value in profile["defines"]]
    args.extend("-I" + windows_to_wsl_path(local_input_path(root, value, allow_root=True)) for value in profile["include_dirs"])
    args.extend(profile["extra_compile_args"])
    return tuple(args)


def validate_profile_sources(profile: dict, source_root: Path) -> dict:
    """Validate declared files and include directories against a local root."""
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    files = relative_paths(_strings(profile.get('source_files'), 'source_files', nonempty=True))
    directories = relative_paths(_strings(profile.get('include_dirs'), 'include_dirs'), allow_root=True)
    rules = relative_paths(_strings(profile.get('semgrep_rule_files', []), 'semgrep_rule_files'))
    missing_files = [x for x in files if not local_input_path(root, x).is_file()]
    missing_dirs = [x for x in directories if not local_input_path(root, x, allow_root=True).is_dir()]
    missing_rules = [x for x in rules if not local_input_path(root, x).is_file()]
    return {"complete": not missing_files and not missing_dirs and not missing_rules,
            "missing_files": missing_files, "missing_include_dirs": missing_dirs,
            "missing_rule_files": missing_rules,
            "source_files": len(profile["source_files"]),
            "include_dirs": len(profile["include_dirs"])}


def validate_profile_provenance(profile: dict, source_root: Path) -> dict:
    """Observe exact Git roots, HEAD and clean tracked/untracked state locally.

    This is not a signature or proof that ignored build inputs belong to HEAD.
    """
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError('source root must be an existing directory')
    repositories = _repositories(profile.get('source_repositories'))
    mismatches, checks = [], []
    for repository, expected in repositories.items():
        check = {'repository': repository, 'expected': expected, 'actual': None, 'clean': False}
        try:
            path = local_input_path(root, repository, allow_root=True)
            if not path.is_dir() or Path(_git(path, 'rev-parse', '--show-toplevel').strip()).resolve() != path:
                raise ValueError('declared path is not the Git worktree root')
            if _git(path, 'config', '--get-regexp', r'^filter\..*\.(clean|smudge|process)$', allow_absent=True):
                raise ValueError('configured Git filters are unsupported during provenance checks')
            check['actual'] = _git(path, 'rev-parse', '--verify', 'HEAD^{commit}').strip().lower()
            # Submodule identities are checked separately when declared. Do not
            # recurse into undeclared submodules and their local configurations.
            check['clean'] = not _git(path, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=all')
            if check['actual'] != expected:
                raise ValueError('repository HEAD does not match profile')
            if not check['clean']:
                raise ValueError('repository has tracked or untracked changes')
            check['status'] = 'matched'
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            check.update(status='unverified', reason=str(exc)[:1024], error_type=type(exc).__name__)
            mismatches.append(dict(check))
        checks.append(check)
    return {"verified": not mismatches, "mismatches": mismatches,
            "repositories": len(repositories), 'checks': checks, 'scope': 'declared_repositories'}


def _git(path, *arguments, allow_absent=False):
    # Do not inherit GIT_DIR/WORK_TREE/INDEX/config injections. Read-only Git
    # commands must not refresh the index or invoke a configured fsmonitor.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    command = ['git', '--no-optional-locks', '--literal-pathspecs', '-c', 'core.fsmonitor=false',
               '-C', str(path), *arguments]
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                            timeout=30, check=False, shell=False, env=env)
    if allow_absent and result.returncode == 1:
        return ''
    if result.returncode != 0:
        raise ValueError('local Git provenance command failed: ' + arguments[0])
    return result.stdout


def prepare_profile(profile_path: Path, source_root: Path, *, selected_files=None):
    """Validate the very bytes whose digest is returned, before analyzer calls."""
    return _prepare_profile_bytes(_read_profile(profile_path), source_root,
                                  selected_files=selected_files)


def _prepare_profile_bytes(raw: bytes, source_root: Path, *, selected_files=None):
    """Shared byte-bound validation for loading or preparing a new profile."""
    if not isinstance(raw, bytes) or len(raw) > _MAX_PROFILE_BYTES:
        raise ValueError('invalid profile bytes or size')
    root = Path(source_root).resolve()
    profile = _decode_profile(raw)
    sources = validate_profile_sources(profile, root)
    if not sources['complete']:
        raise ValueError('profile input files or directories missing: ' + json.dumps(sources, sort_keys=True))
    if selected_files is not None:
        selected = relative_paths(selected_files, nonempty=True)
        declared = {os.path.normcase(x) for x in profile['source_files']}
        if any(os.path.normcase(x) not in declared for x in selected):
            raise ValueError('selected source is not declared in profile')
    repo_paths = [local_input_path(root, x, allow_root=True) for x in profile['source_repositories']]
    for name in profile['source_files'] + profile['include_dirs']:
        path = local_input_path(root, name, allow_root=True)
        owners = [repo for repo in repo_paths if path.is_relative_to(repo)]
        if not owners:
            raise ValueError('profile input is outside declared repository coverage: ' + name)
        expected_owner = max(owners, key=lambda p: len(p.parts))
        observed_owner = Path(_git(path if path.is_dir() else path.parent, 'rev-parse', '--show-toplevel').strip()).resolve()
        if observed_owner != expected_owner:
            raise ValueError('profile input belongs to an undeclared nested repository: ' + name)
    provenance = validate_profile_provenance(profile, root)
    if not provenance['verified']:
        raise ValueError('profile provenance rejected: ' + json.dumps(provenance['mismatches'], sort_keys=True))
    # Selected target files must actually be tracked; ignored or index-hidden
    # inputs cannot silently inherit the containing repository's commit claim.
    for name in profile['source_files']:
        path = local_input_path(root, name)
        repo = max((p for p in repo_paths if path.is_relative_to(p)), key=lambda p: len(p.parts))
        flag = _git(repo, 'ls-files', '-v', '-z', '--', path.relative_to(repo).as_posix())
        if not flag or flag[0] != 'H':
            raise ValueError('profile target must be tracked without index concealment: ' + name)
    rule_hashes = {name: hashlib.sha256(local_input_path(root, name).read_bytes()).hexdigest()
                   for name in profile['semgrep_rule_files']}
    expected = profile.get('semgrep_rule_sha256')
    if expected is not None and any(rule_hashes[name] != expected[name].lower() for name in rule_hashes):
        raise ValueError('profile rule digest mismatch')
    receipt = {'schema': 'profile-validation-0.1', 'profile_sha256': hashlib.sha256(raw).hexdigest(),
               'source_root': str(root), 'provenance': provenance, 'inputs': sources,
               'semgrep_rule_sha256': rule_hashes}
    return profile, receipt


def recheck_profile(profile_path, source_root, profile, receipt):
    if hashlib.sha256(_read_profile(profile_path)).hexdigest() != receipt['profile_sha256']:
        raise ValueError('profile changed during analysis')
    current = validate_profile_provenance(profile, source_root)
    if not current['verified'] or current != receipt['provenance']:
        raise ValueError('profile provenance changed during analysis')
