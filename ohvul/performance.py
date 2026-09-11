"""Offline synthetic scanner performance benchmark."""
import tempfile, time
from pathlib import Path
from .detect.scanner import scan_path
import argparse, json

def benchmark_scan(*, files=10, lines=20):
    if not isinstance(files,int) or not 1 <= files <= 10000 or not isinstance(lines,int) or not 1 <= lines <= 1000: raise ValueError('benchmark bounds exceeded')
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory); code='int x;\n' * lines
        for index in range(files): (root / f'sample_{index}.c').write_text(code, encoding='utf-8')
        start=time.perf_counter(); result=scan_path(root); elapsed=time.perf_counter()-start
    return {'schema':'0.1','files':files,'lines_per_file':lines,'elapsed_seconds':elapsed,'files_per_second':files/elapsed if elapsed else None,'findings':len(result['findings']),'local_only':True,'no_execution':True}

def benchmark_matrix(scales=(1, 10, 100)):
    if not isinstance(scales, (list, tuple)) or not scales or any(not isinstance(x, int) or x < 1 or x > 10000 for x in scales): raise ValueError('invalid benchmark scales')
    return {'schema':'0.1','runs':[benchmark_scan(files=x) for x in scales], 'local_only':True, 'no_execution':True}

def compare_throughput(baseline, current, max_regression=0.2):
    if not isinstance(baseline, dict) or not isinstance(current, dict): raise ValueError('invalid performance result')
    old, new = baseline.get('files_per_second'), current.get('files_per_second')
    if not isinstance(old, (int,float)) or old <= 0 or not isinstance(new, (int,float)) or new < 0: raise ValueError('invalid throughput')
    if not isinstance(max_regression, (int,float)) or not 0 <= max_regression < 1: raise ValueError('invalid regression threshold')
    regression=(old-new)/old
    return {'schema':'0.1','regression':regression,'within_budget':regression <= max_regression,'review_required':True,'local_only':True}

def validate_performance_result(result):
    if not isinstance(result, dict) or result.get('schema') != '0.1': raise ValueError('invalid performance schema')
    if not isinstance(result.get('files'), int) or not isinstance(result.get('elapsed_seconds'), (int,float)) or result['elapsed_seconds'] < 0: raise ValueError('invalid performance metrics')
    if not isinstance(result.get('files_per_second'), (int,float)) or result['files_per_second'] < 0: raise ValueError('invalid throughput metric')
    if result.get('local_only') is not True or result.get('no_execution') is not True: raise ValueError('unsafe performance result')
    return True

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--files',type=int,default=10); p.add_argument('--lines',type=int,default=20); args=p.parse_args()
    try:
        result=benchmark_scan(files=args.files,lines=args.lines); validate_performance_result(result)
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except ValueError as exc: print(f'INVALID: {exc}'); return 1

if __name__ == '__main__': raise SystemExit(main())
