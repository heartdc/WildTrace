"""Offline synthetic scanner performance benchmark."""
import tempfile, time, tracemalloc
from pathlib import Path
from .detect.scanner import scan_path
import argparse, json
from pathlib import Path

def benchmark_scan(*, files=10, lines=20):
    if not isinstance(files,int) or not 1 <= files <= 10000 or not isinstance(lines,int) or not 1 <= lines <= 1000: raise ValueError('benchmark bounds exceeded')
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory); code='int x;\n' * lines
        for index in range(files): (root / f'sample_{index}.c').write_text(code, encoding='utf-8')
        tracemalloc.start(); start=time.perf_counter(); result=scan_path(root); elapsed=time.perf_counter()-start
        _, peak_memory = tracemalloc.get_traced_memory(); tracemalloc.stop()
    return {'schema':'0.1','files':files,'lines_per_file':lines,'elapsed_seconds':elapsed,'files_per_second':files/elapsed if elapsed else None,'peak_memory_bytes':peak_memory,'findings':len(result['findings']),'local_only':True,'no_execution':True}

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
    if not isinstance(result.get('peak_memory_bytes'), int) or result['peak_memory_bytes'] < 0: raise ValueError('invalid memory metric')
    if result.get('local_only') is not True or result.get('no_execution') is not True: raise ValueError('unsafe performance result')
    return True

def save_performance_result(result, path):
    validate_performance_result(result); path=Path(path)
    if path.exists() or path.is_symlink(): raise FileExistsError('performance result already exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2); stream.write('\n')

def load_performance_result(path):
    result=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    validate_performance_result(result)
    return result

def format_performance_report(matrix):
    if not isinstance(matrix, dict) or matrix.get('schema') != '0.1' or not isinstance(matrix.get('runs'), list): raise ValueError('invalid performance matrix')
    lines=['# Synthetic Performance Benchmark','', '| Files | Seconds | Files per second | Peak memory bytes | Findings |','|---:|---:|---:|---:|---:|']
    for run in matrix['runs']:
        validate_performance_result(run)
        lines.append(f"| {run['files']} | {run['elapsed_seconds']:.6f} | {run['files_per_second']:.2f} | {run['peak_memory_bytes']} | {run['findings']} |")
    lines += ['', 'Results are synthetic, local-only measurements and do not establish a vulnerability verdict.']
    return '\n'.join(lines) + '\n'

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--files',type=int,default=10); p.add_argument('--lines',type=int,default=20); args=p.parse_args()
    try:
        result=benchmark_scan(files=args.files,lines=args.lines); validate_performance_result(result)
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except ValueError as exc: print(f'INVALID: {exc}'); return 1

if __name__ == '__main__': raise SystemExit(main())
