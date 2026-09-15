"""Offline import of explicit compilation argument vectors into profile drafts.

This deliberately supports only the subset faithfully representable by the
existing engine-profile contract. Commands, wrappers and unknown options are
not executed or guessed. Drafts still require ordinary provenance validation.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path, PureWindowsPath
import re

from .component_batch import _path
from .engine_profile import _decode_profile, validate_profile
from .review_queue import (canonical_bytes, decode_json, exclusive_json,
                           read_bounded, recheck_inputs, sha256, _require)

MAX_DATABASE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 2048
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
_DRIVER = re.compile(r'(?:clang(?:\+\+)?|gcc|g\+\+|cc|c\+\+)(?:-\d+(?:\.\d+)*)?(?:\.exe)?')
_FIXED = {'-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread', '-fno-exceptions',
          '-fno-rtti', '-fno-common', '-fno-strict-aliasing', '-O2'}


class _Blocked(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _need(condition, code):
    if not condition:
        raise _Blocked(code)


def _text(value):
    return (isinstance(value, str) and 0 < len(value) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _local(value, parent, root):
    _need(_text(value), 'invalid_local_path')
    try:
        result = _path(value, parent)
    except (OSError, ValueError):
        raise _Blocked('invalid_or_linked_path') from None
    _need(result.is_relative_to(root), 'path_outside_source_root')
    return result


def _unit(entry, index, root, database_parent, template):
    _need(isinstance(entry, dict) and not set(entry) - {
        'directory', 'file', 'arguments', 'command', 'output'}, 'invalid_entry_fields')
    _need('arguments' in entry, 'argument_vector_required')
    arguments = entry['arguments']
    _need(isinstance(arguments, list) and 2 <= len(arguments) <= 512
          and all(_text(arg) for arg in arguments), 'invalid_argument_vector')
    _need('command' not in entry or _text(entry['command']), 'invalid_command_metadata')
    directory = _local(entry.get('directory'), database_parent, root)
    _need(directory.is_dir(), 'compilation_directory_missing')
    source = _local(entry.get('file'), directory, root)
    _need(source.is_file(), 'source_file_missing')
    _need(source.suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}, 'unsupported_source_type')
    _need(_DRIVER.fullmatch(PureWindowsPath(arguments[0]).name) is not None,
          'unsupported_compiler_driver')
    includes, defines, extras, omitted, source_args = [], [], [], [], []
    output = None
    has_compile = False
    standard_seen = False
    position = 1
    while position < len(arguments):
        flag = arguments[position]
        position += 1
        if flag == '-c':
            _need(not has_compile, 'duplicate_compile_switch')
            has_compile = True
            omitted.append({'option': '-c', 'reason': 'analysis_uses_its_own_driver_mode'})
            continue
        if flag in {'-MMD', '-MD', '-MP'}:
            omitted.append({'option': flag, 'reason': 'dependency_output_not_executed'})
            continue
        option, value = None, None
        for name in ('-I', '-D', '-o', '-MF', '-MT', '-MQ'):
            if flag == name:
                _need(position < len(arguments), 'missing_option_value')
                option, value = name, arguments[position]
                position += 1
                break
            if flag.startswith(name) and len(flag) > len(name):
                option, value = name, flag[len(name):]
                break
        if option == '-I':
            path = _local(value, directory, root)
            _need(path.is_dir(), 'include_directory_missing')
            includes.append(path.relative_to(root).as_posix())
        elif option == '-D':
            defines.append(value)
        elif option in ('-o', '-MF'):
            path = _local(value, directory, root)
            if option == '-o':
                _need(output is None, 'duplicate_output_option')
                output = path
            omitted.append({'option': option, 'path': path.relative_to(root).as_posix(),
                            'reason': 'compiler_output_not_executed'})
        elif option in ('-MT', '-MQ'):
            # Dependency targets are not source or executable input.
            omitted.append({'option': option, 'value_sha256': sha256(value.encode('utf8')),
                            'reason': 'dependency_target_not_executed'})
        elif flag in _FIXED or re.fullmatch(r'-Wno-[A-Za-z0-9_+\-]+', flag):
            extras.append(flag)
        elif flag.startswith('-std='):
            _need(not standard_seen, 'conflicting_language_standards')
            standard_seen = True
            extras.append(flag)
        elif flag.startswith(('-', '@')):
            raise _Blocked('unsupported_compile_argument')
        else:
            source_args.append(_local(flag, directory, root))
    _need(has_compile, 'compile_switch_required')
    _need(source_args == [source], 'source_argument_mismatch')
    if 'output' in entry:
        declared_output = _local(entry['output'], directory, root)
        _need(output is None or output == declared_output, 'output_metadata_mismatch')
    profile = {key: copy.deepcopy(template[key]) for key in (
        'schema', 'component', 'source_repositories', 'engines')}
    profile.update(source_files=[source.relative_to(root).as_posix()], include_dirs=includes,
                   defines=defines, extra_compile_args=extras,
                   status='compile-database-draft-not-provenance-verified',
                   disclaimer='Argument import only; repository pins still require execution-time validation.')
    try:
        profile = validate_profile(profile)
    except ValueError:
        raise _Blocked('unsupported_or_conflicting_profile_options') from None
    identity = {'source_file': profile['source_files'][0],
                'working_directory': directory.relative_to(root).as_posix(),
                'defines': defines, 'include_dirs': includes, 'extra_compile_args': extras,
                'compiler_identifier': arguments[0]}
    config_hash = sha256(canonical_bytes(identity))
    unit_id = 'unit-' + str(index + 1).zfill(4) + '-' + config_hash[:12]
    return {'index': index, 'status': 'imported', 'unit_id': unit_id,
            'configuration_sha256': config_hash, 'entry_sha256': sha256(canonical_bytes(entry)),
            'arguments_sha256': sha256(canonical_bytes(arguments)),
            'working_directory': identity['working_directory'],
            'source_file': identity['source_file'], 'profile_draft': profile,
            'excluded_driver_arguments': omitted, 'command_string_ignored': 'command' in entry}, source


def _build(database, source_root, template):
    database = _path(str(database), Path.cwd())
    root = _path(str(source_root), Path.cwd())
    template_path = _path(str(template), Path.cwd())
    _require(root.is_dir(), 'source root must be an existing local directory')
    raw = read_bounded(database, MAX_DATABASE_BYTES)
    template_raw = read_bounded(template_path, 1024 * 1024)
    entries = decode_json(raw)
    _require(isinstance(entries, list) and 1 <= len(entries) <= MAX_ENTRIES,
             'database must be a bounded nonempty entry list')
    profile = _decode_profile(template_raw)
    _require(set(profile['engines']) <= {'clang-static-analyzer', 'clang-tidy'},
             'template must select only supported Clang engines')
    captured = [(database, raw, MAX_DATABASE_BYTES), (template_path, template_raw, 1024 * 1024)]
    units, files, directories, identities = [], {}, set(), set()
    for index, entry in enumerate(entries):
        try:
            unit, source = _unit(entry, index, root, database.parent, profile)
            _need(unit['configuration_sha256'] not in identities, 'duplicate_configuration')
            if source not in files:
                content = read_bounded(source, MAX_SOURCE_BYTES)
                _need(sum(len(x) for x in files.values()) + len(content) <= MAX_TOTAL_SOURCE_BYTES,
                      'source_byte_budget_exceeded')
                files[source] = content
                captured.append((source, content, MAX_SOURCE_BYTES))
            content = files[source]
            unit.update(source_file_sha256=sha256(content), source_file_bytes=len(content))
            identities.add(unit['configuration_sha256'])
            directories.add(root / unit['working_directory'])
            directories.update(root / name for name in unit['profile_draft']['include_dirs'])
            units.append(unit)
        except _Blocked as exc:
            units.append({'index': index, 'status': 'blocked', 'error_code': exc.code,
                          'entry_sha256': sha256(canonical_bytes(entry))})
        except (OSError, ValueError):
            units.append({'index': index, 'status': 'blocked', 'error_code': 'source_input_read_failed',
                          'entry_sha256': sha256(canonical_bytes(entry))})
    imported = sum(unit['status'] == 'imported' for unit in units)
    result = {'schema': 'compile-database-import-0.1',
              'status': 'drafts_ready' if imported == len(units) else 'partial' if imported else 'blocked',
              'database_sha256': sha256(raw), 'template_sha256': sha256(template_raw),
              'source_root': str(root), 'counts': {'entries': len(units), 'imported': imported,
                                                 'blocked': len(units) - imported},
              'units': units, 'provenance_verified': False, 'commands_executed': False,
              'analyzers_run': False, 'target_executed': False, 'network_invoked': False,
              'limitations': [
                  'Only the explicitly supported argument-vector subset is imported; command strings are not parsed.',
                  'Template pins and engine selection are retained; template source lists and compile flags are not inherited.',
                  'Each accepted compilation configuration has its own profile; unknown inputs are not silently dropped.',
                  'Drafts still require ordinary profile source and repository provenance validation.',
                  'Host/compiler builtins, sysroots, transitive headers and product semantics are not verified.',
                  'Only original input/source bytes and declared directory existence are checked; this is not an immutable snapshot.']}
    _require(len(canonical_bytes(result)) <= MAX_OUTPUT_BYTES, 'import output byte limit exceeded')
    def recheck():
        recheck_inputs(captured)
        for directory in directories:
            _require(_path(str(directory), root).is_dir(), 'input directory changed during import')
    recheck()
    return result, recheck


def build_import(database, source_root, template):
    return _build(database, source_root, template)[0]


def _artifacts(result):
    values = {unit['unit_id'] + '.profile.json': unit['profile_draft'] for unit in result['units']
              if unit['status'] == 'imported'}
    # Never offer a successful-looking batch that quietly omits failed entries.
    if result['status'] == 'drafts_ready':
        values['batch.json'] = {'schema': 'component-batch-0.1', 'jobs': [
            {'id': unit['unit_id'], 'source_root': result['source_root'],
             'profile': unit['unit_id'] + '.profile.json'} for unit in result['units']]}
    return values


def write_import(database, source_root, template, output):
    output = _path(str(output), Path.cwd())
    root = _path(str(source_root), Path.cwd())
    _require(not output.exists() and output.parent.is_dir(), 'output must be a new directory with an existing parent')
    _require(not output.is_relative_to(root) and not root.is_relative_to(output), 'output/source collision')
    for path in (database, template):
        _require(not _path(str(path), Path.cwd()).is_relative_to(output), 'output/input collision')
    result, recheck = _build(database, root, template)
    recheck()
    output.mkdir()
    for name, value in _artifacts(result).items():
        exclusive_json(output / name, value, before_publish=recheck)
    exclusive_json(output / 'summary.json', result, before_publish=recheck)
    return result


def verify_import(database, source_root, template, output):
    result, recheck = _build(database, source_root, template)
    output = _path(str(output), Path.cwd())
    expected = {**_artifacts(result), 'summary.json': result}
    captured = []
    for name, value in expected.items():
        raw = read_bounded(output / name, MAX_OUTPUT_BYTES)
        _require(canonical_bytes(decode_json(raw)) == canonical_bytes(value), 'saved import differs from current input')
        captured.append((output / name, raw, MAX_OUTPUT_BYTES))
    _require({p.name for p in output.iterdir()} == set(expected), 'unexpected or missing import artifact')
    recheck()
    recheck_inputs(captured)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('database', 'source-root', 'template', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    try:
        function = verify_import if args.verify else write_import
        result = function(args.database, args.source_root, args.template, args.output)
        print(json.dumps({'status': result['status'], 'counts': result['counts'],
                          'provenance_verified': False, 'commands_executed': False}))
        return 0 if result['status'] == 'drafts_ready' else 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('COMPILE_IMPORT_REJECTED ' + type(exc).__name__)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
