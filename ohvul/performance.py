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

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--files',type=int,default=10); p.add_argument('--lines',type=int,default=20); args=p.parse_args()
    try: print(json.dumps(benchmark_scan(files=args.files,lines=args.lines),ensure_ascii=False,indent=2)); return 0
    except ValueError as exc: print(f'INVALID: {exc}'); return 1

if __name__ == '__main__': raise SystemExit(main())
