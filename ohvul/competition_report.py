"""Assemble the competition vulnerability report from per-case records.

Competition audit 2026-09-23 (P1.7): the existing report layer projects
candidate identifiers only, and hand-written summaries drift from the
per-case records. This assembler is a *defensive projection* of
``cases/*/case.json`` (several schema generations coexist) into one
deterministic report:

* every field is taken from the case record or marked ``unknown`` —
  nothing is inferred, no confirmed-vulnerability count is ever invented;
* human conclusions and runtime evidence stay referenced, never re-typed;
* a completeness matrix exposes, per case, which evidence layers exist.

It never executes targets, reads binaries, or touches the network.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .review_queue import checked_path, exclusive_json

SCHEMA = 'wildtrace-competition-report-0.1'

# 完整度六维（与 docs/status/CASE_LEDGER_20260924.md 对齐）
DIMENSIONS = ('source_verification', 'equivalent_or_runtime_reproduction',
              'product_impact', 'fix_reference', 'submission_record',
              'official_acceptance')


def _load_case(path: Path) -> dict:
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError(f'case record must be an object: {path}')
    return data


def _first(record: dict, *keys):
    for key in keys:
        if key in record and record[key] not in (None, '', [], {}):
            return record[key]
    return None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _tier_flags(record: dict) -> dict:
    submission = record.get('submission')
    submission = submission if isinstance(submission, dict) else None
    validation = record.get('validation_evidence')
    validation = validation if isinstance(validation, dict) else {}
    scope = record.get('runtime_scope')
    scope = scope if isinstance(scope, dict) else {}
    runtime_status = record.get('runtime_status')
    return {
        'source_verification': bool(_first(record, 'discovery_method', 'cve_reference',
                                           'public_cve_reference', 'candidate')),
        'equivalent_or_runtime_reproduction': bool(
            (isinstance(runtime_status, str) and runtime_status not in ('not_run', None))
            or validation.get('asan') or record.get('source_equivalent_result')),
        'product_impact': bool(
            (isinstance(record.get('product_reachability'), str)
             and record['product_reachability'] != 'not_established')
            or scope.get('open_harmony_binary_linked')),
        'fix_reference': bool(_first(record, 'expected_commit', 'upstream_sources',
                                     'public_upstream', 'patch')),
        'submission_record': bool(submission and submission.get('ticket')),
        'official_acceptance': bool(submission and submission.get('official_status')),
    }


def project_case(record: dict, name: str) -> dict:
    """Project one case record; unknown layers stay explicit."""
    submission = record.get('submission')
    submission = submission if isinstance(submission, dict) else {}
    flags = _tier_flags(record)
    return {
        'case': name,
        'case_id': _first(record, 'case_id', 'id') or name,
        'component': _first(record, 'component') or 'unknown',
        'cve': _first(record, 'cve_reference', 'public_cve_reference') or 'none',
        'cwe': _as_list(record.get('cwe_candidate')) or ['unknown'],
        'new_discovery': bool(record.get('new_discovery', False)),
        'discovery_method': _first(record, 'discovery_method') or 'unknown',
        'runtime_status': record.get('runtime_status')
            or ('equivalent_reproduction' if record.get('validation_evidence') else 'unknown'),
        'product_impact': 'not_established'
            if not flags['product_impact'] else 'referenced',
        'submission': {
            'ticket': submission.get('ticket') or 'none',
            'status': submission.get('status') or 'not_submitted',
            'official_status': submission.get('official_status') or 'unknown',
        },
        'confirmed_vulnerability': bool(record.get('confirmed_vulnerability', False)),
        'evidence_dimensions': flags,
        'missing_dimensions': [d for d in DIMENSIONS if not flags[d]],
    }


def assemble(cases_root: Path) -> dict:
    cases_root = checked_path(cases_root)
    if not cases_root.is_dir():
        raise ValueError('cases root must be a directory')
    projected = []
    for path in sorted(cases_root.glob('*/case.json')):
        projected.append(project_case(_load_case(path), path.parent.name))
    if not projected:
        # an empty report must not look like a successful run (audit C11)
        raise ValueError(f'no case records found under {cases_root} (*/case.json)')
    confirmed = sum(1 for case in projected if case['confirmed_vulnerability'])
    return {
        'schema': SCHEMA,
        'cases_root': str(cases_root),
        'case_count': len(projected),
        # 口径纪律：仅投影 case.json 的显式 confirmed_vulnerability 字段，不推断
        'confirmed_vulnerabilities': confirmed,
        'submitted_tickets': sorted({c['submission']['ticket']
                                     for c in projected if c['submission']['ticket'] != 'none'}),
        'official_acceptance': sorted({c['submission']['official_status']
                                       for c in projected
                                       if c['submission']['official_status'] not in ('unknown', 'none')}),
        'completeness': {
            dimension: sum(1 for c in projected if c['evidence_dimensions'][dimension])
            for dimension in DIMENSIONS
        },
        'cases': projected,
        'statement': ('Fields are projections of cases/*/case.json only; absent layers are '
                      'marked unknown and are not inferred. Confirmed product vulnerabilities '
                      'require platform-level evidence per case records.'),
    }


def render_markdown(report: dict) -> str:
    lines = ['# WildTrace 漏洞报告（组装稿）', '']
    lines.append(f"- 案例数：{report['case_count']}（源：`{report['cases_root']}` 各 case.json 投影）")
    lines.append(f"- 已提交工单：{len(report['submitted_tickets'])} 张"
                 + (f"（{', '.join(report['submitted_tickets'])}）" if report['submitted_tickets'] else ''))
    lines.append(f"- 官方接受：{report['official_acceptance'] or '无记录（未知）'}")
    lines.append(f"- 确认产品漏洞数：{report['confirmed_vulnerabilities']}"
                 '（仅投影各案 confirmed_vulnerability 字段，不做推断）')
    lines.append('')
    lines.append('## 证据完整度矩阵')
    lines.append('')
    header = ['案例'] + ['源码核验', '等价/运行时复现', '产品影响', '修复参照', '提交记录', '官方接受']
    lines.append('| ' + ' | '.join(header) + ' |')
    lines.append('|' + '---|' * len(header))
    for case in report['cases']:
        row = [case['case']] + ['✓' if case['evidence_dimensions'][d] else '—' for d in DIMENSIONS]
        lines.append('| ' + ' | '.join(row) + ' |')
    lines.append('')
    lines.append('## 分案记录')
    for case in report['cases']:
        lines.append('')
        lines.append(f"### {case['case_id']}")
        lines.append(f"- CVE：{case['cve']}｜CWE：{', '.join(case['cwe'])}")
        lines.append(f"- 组件：{case['component']}")
        lines.append(f"- 发现方式：{case['discovery_method']}（new_discovery={case['new_discovery']}）")
        lines.append(f"- 运行时状态：{case['runtime_status']}｜产品影响：{case['product_impact']}")
        lines.append(f"- 提交：{case['submission']['ticket']}"
                     f"（{case['submission']['status']}，官方 {case['submission']['official_status']}）")
        missing = case['missing_dimensions']
        lines.append(f"- 缺失维度：{', '.join(missing) if missing else '无'}")
    lines.append('')
    lines.append('> ' + report['statement'])
    lines.append('')
    return chr(10).join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=Path('cases'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args(argv)
    report = assemble(args.cases)
    # markdown first, JSON last: a failure halfway must not leave the JSON
    # published without its markdown half (audit C11 partial-run window)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        with args.markdown.open('x', encoding='utf-8', newline=chr(10)) as stream:
            stream.write(render_markdown(report))
    exclusive_json(args.output, report)
    print(f"COMPETITION_REPORT cases={report['case_count']} "
          f"confirmed={report['confirmed_vulnerabilities']} "
          f"tickets={len(report['submitted_tickets'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
