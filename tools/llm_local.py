"""Local operator entry: inspect a plan, then opt in to bounded remote review.

Credentials are entered with getpass or read from an explicitly selected process
environment. They are never command arguments, JSON configuration or files.
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys
import warnings

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from ohvul import llm_review as review
from ohvul.llm_adapter import LlmTransportError, reject_credentials, runtime_key, validate_settings
from ohvul.review_queue import checked_path, read_bounded, decode_json, _require

DEFAULT_CONFIG = PROJECT / 'docs/profiles/llm_operator_20260914.json'
FIELDS = {'schema', 'summary', 'queue', 'context', 'evidence', 'source_roots',
          'groups', 'base_url', 'model', 'timeout', 'max_tokens', 'max_calls'}


def _path(value):
    _require(isinstance(value, str) and value.strip() == value and bool(value), 'invalid configured path')
    path = Path(value)
    return checked_path(path if path.is_absolute() else PROJECT / path)


def load_config(path):
    raw = read_bounded(path, 32768)
    reject_credentials(raw)
    config = decode_json(raw)
    _require(isinstance(config, dict) and set(config) == FIELDS
             and config['schema'] == 'llm-local-operator-0.1', 'invalid operator configuration')
    validate_settings(config['base_url'], config['model'], config['timeout'], config['max_tokens'])
    _require(type(config['max_calls']) is int and 1 <= config['max_calls'] <= review.MAX_CALLS,
             'invalid configured call budget')
    _require(isinstance(config['groups'], list) and 1 <= len(config['groups']) <= config['max_calls']
             and all(isinstance(g, str) and g for g in config['groups'])
             and len(set(config['groups'])) == len(config['groups']), 'explicit unique groups required')
    _require(isinstance(config['source_roots'], dict) and bool(config['source_roots'])
             and all(isinstance(job, str) and bool(job) for job in config['source_roots']),
             'explicit job roots required')
    for name in ('summary', 'queue', 'context'):
        config[name] = _path(config[name])
    config['evidence'] = None if config['evidence'] is None else _path(config['evidence'])
    config['source_roots'] = {job: _path(root) for job, root in config['source_roots'].items()}
    return config


def _prompt_key():
    _require(sys.stdin.isatty(), 'interactive secret entry requires a local terminal')
    # Fail closed if getpass cannot disable echo; never fall back to ordinary input.
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        return runtime_key(getpass.getpass('API key (hidden, not saved): '))


def _summary(value):
    if value.get('schema') == 'llm-review-inspection-0.1':
        print('INSPECTION', value['status'], 'reasoning_verified=False')
        value = value['summary']
    allowed = ('status', 'calls_attempted', 'valid_drafts', 'failed_calls',
               'selected_groups_not_run', 'queue_groups_total', 'queue_groups_not_selected',
               'usage', 'confirmed_vulnerabilities')
    print(json.dumps({k: value[k] for k in allowed if k in value}, ensure_ascii=False, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'run', 'verify', 'inspect'))
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--group', action='append', help='explicitly override groups; does not change call budget')
    parser.add_argument('--allow-network', action='store_true')
    parser.add_argument('--key-source', choices=('prompt', 'environment'), default='prompt')
    args = parser.parse_args(argv)
    key = None
    try:
        _require(args.mode != 'run' or args.allow_network, 'run requires --allow-network')
        _require(args.mode == 'run' or (not args.allow_network and args.key_source == 'prompt'),
                 'offline modes do not read credentials or allow network')
        config_path = checked_path(args.config)
        raw_config = read_bounded(config_path, 32768)
        config = load_config(config_path)
        output = checked_path(args.output)
        _require(not config_path.is_relative_to(output), 'output conflicts with operator config')
        inputs = [config[k] for k in ('summary', 'queue', 'context', 'source_roots')]
        evidence = config['evidence']
        groups = config['groups'] if args.group is None else args.group
        settings = dict(base_url=config['base_url'], model=config['model'], timeout=config['timeout'],
                        max_tokens=config['max_tokens'], max_calls=config['max_calls'])
        if args.mode in ('inspect', 'verify'):
            function = review.inspect_review if args.mode == 'inspect' else review.verify_review
            value = function(output, *inputs, evidence_path=evidence)
            _summary(value)
            return 0
        # Check all input, output and budget conditions before requesting a secret.
        review._output(output, *inputs)
        if evidence is not None:
            _require(not evidence.is_relative_to(output), 'output conflicts with expansion input')
        queue, context, captured, recheck = review._load(*inputs, evidence)
        plan = review._plan(queue, context, captured, groups, **settings)
        recheck()
        print('SELECTED_GROUPS', len(groups), 'OF', plan['queue_groups_total'],
              'MAX_CALLS', plan['max_calls'], 'TIMEOUT_SECONDS', plan['timeout'],
              'MAX_REQUESTED_OUTPUT_TOKENS', plan['maximum_requested_output_tokens'], flush=True)
        if args.mode == 'run':
            key = _prompt_key() if args.key_source == 'prompt' else runtime_key()
        _require(read_bounded(config_path, 32768) == raw_config, 'operator config changed before execution')
        value = review.run_review(*inputs, output, groups, plan_only=args.mode == 'plan',
                                  allow_network=args.mode == 'run', api_key=key,
                                  evidence_path=evidence, **settings)
        _summary(value)
        if args.mode == 'run':
            # Success and failure records are checked without another paid call.
            inspection = review.inspect_review(output, *inputs, evidence_path=evidence)
            print('SAVED_RECORDS', inspection['status'], 'reasoning_verified=False')
        return 0 if value['status'] in ('prepared', 'completed') else 1
    except (OSError, ValueError, TypeError, KeyError, LlmTransportError, getpass.GetPassWarning) as exc:
        # Do not print arbitrary response/config/exception text or a credential.
        print('LOCAL_REVIEW_REJECTED', type(exc).__name__, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('LOCAL_REVIEW_CANCELLED; inspect existing outputs before starting another run', file=sys.stderr)
        return 130
    finally:
        key = None  # Python does not promise memory erasure.


if __name__ == '__main__':
    raise SystemExit(main())
