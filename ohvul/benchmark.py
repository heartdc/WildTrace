"""Offline candidate-rule benchmark; never executes target code."""
import argparse,json,re,tempfile
from pathlib import Path
from .detect.scanner import scan_path
from .detect.function_rules import scan_functions

SCANNERS={'builtin':scan_path,'function_rules':scan_functions}

def validate_cases(cases):
 """Validate all annotations before creating files or scanning any case."""
 if not isinstance(cases, list):
  raise ValueError('benchmark must be an array')
 fields = {'id', 'code', 'expected_cwe', 'label', 'reason', 'language', 'component'}
 labels = {'candidate', 'reviewed_suppressed', 'candidate_requires_context', 'safe_control'}
 seen = set()
 for index, case in enumerate(cases):
  prefix = f'case[{index}]'
  if not isinstance(case, dict) or set(case) != fields:
   raise ValueError(f'{prefix}: exact benchmark fields required')
  for field in fields - {'expected_cwe'}:
   if not isinstance(case[field], str) or not case[field].strip():
    raise ValueError(f'{prefix}: {field} must be a nonempty string')
  if case['id'] in seen:
   raise ValueError(f'{prefix}: duplicate id')
  seen.add(case['id'])
  if case['label'] not in labels:
   raise ValueError(f'{prefix}: unsupported label')
  if case['language'] not in {'C', 'C++'}:
   raise ValueError(f'{prefix}: unsupported language')
  expected = case['expected_cwe']
  if not isinstance(expected, list) or any(
   not isinstance(value, str) or not re.fullmatch(r'CWE-[1-9][0-9]*', value)
   for value in expected
  ):
   raise ValueError(f'{prefix}: expected_cwe must be an array of CWE identifiers')
  if len(expected) != len(set(expected)):
   raise ValueError(f'{prefix}: duplicate expected CWE')
  if (case['label'] in {'safe_control', 'reviewed_suppressed'}) != (not expected):
   raise ValueError(f'{prefix}: label and expected_cwe disagree')

def evaluate(cases,*,scan=scan_path):
 validate_cases(cases)
 results=[]; tp=fp=fn=0; groups={}
 for case in cases:
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); path=root/('sample.cpp' if case['language']=='C++' else 'sample.c'); path.write_text(case['code'],encoding='utf-8'); observed={x['cwe_candidate'] for x in scan(root)['findings']}; expected=set(case['expected_cwe']);
   case_tp=len(observed & expected); case_fp=len(observed-expected); case_fn=len(expected-observed); tp+=case_tp; fp+=case_fp; fn+=case_fn; key=f"{case.get('component','unknown')}::{case.get('language','unknown')}"; group=groups.setdefault(key,{'cases':0,'tp':0,'fp':0,'fn':0}); group['cases']+=1; group['tp']+=case_tp; group['fp']+=case_fp; group['fn']+=case_fn
   results.append({'id':case['id'],'label':case.get('label'),'expected':sorted(expected),'observed':sorted(observed),'true_positive_candidates':case_tp,'false_positive_candidates':case_fp,'false_negative_candidates':case_fn,'rule_overlap':len(observed)>1,'reason':case.get('reason','')})
 return {'benchmark_schema':'0.1','cases':len(cases),'candidate_metrics':{'tp':tp,'fp':fp,'fn':fn,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None},'rule_overlap_cases':sum(x['rule_overlap'] for x in results),'groups':groups,'results':results,'disclaimer':'Candidate-rule statistics only; no vulnerability verdict.'}

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('benchmark',type=Path); p.add_argument('--scanner',choices=sorted(SCANNERS),default='builtin'); a=p.parse_args()
 try: data=json.loads(a.benchmark.read_text(encoding='utf-8-sig')); result=evaluate(data,scan=SCANNERS[a.scanner]); print(json.dumps(result,ensure_ascii=True,indent=2))
 except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc: print(f'INVALID: {exc}'); return 1
 return 0
if __name__=='__main__': raise SystemExit(main())


