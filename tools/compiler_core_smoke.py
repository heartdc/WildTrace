"""Real Clang static-only contrast run in an exclusive synthetic Git workspace."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.compiler_analysis import run_compiler_profile
from ohvul.review_queue import checked_path, exclusive_json
from ohvul.report.schema import build_audit_report, validate_report_against_result
from ohvul.verify import validate_result

POSITIVE = {'write_overflow':'CWE-787','read_overflow':'CWE-125',
            'offset_overflow':'CWE-787','typed_overflow':'CWE-787',
            'pointer_size_overflow':'CWE-787','macro_overflow':'CWE-787',
            'fill_overflow':'CWE-787','address_overflow':'CWE-787',
            'cpp_write_overflow':'CWE-787', 'local_length_overflow':'CWE-787',
            'derived_length_overflow':'CWE-787', 'loop_fresh_overflow':'CWE-787',
            'local_offset_overflow':'CWE-787', 'cpp_local_overflow':'CWE-787'}
NEGATIVE = {'write_fixed','read_fixed','offset_fixed','typed_fixed','narrowed_fixed',
            'macro_fixed','fill_fixed','dead_branch','address_fixed','sizeof_unevaluated','cpp_write_fixed',
            'dead_shortcircuit','dead_conditional','dead_while', 'local_length_fixed',
            'branch_join_fixed', 'local_dead_fixed', 'local_narrow_fixed',
            'local_offset_fixed', 'local_return_fixed'}
UNKNOWN = {'dynamic_unknown','indirect_unknown','cpp_custom_unknown', 'branch_join_unknown',
           'escaped_length_unknown','loop_length_unknown','volatile_length_unknown',
           'cpp_reference_unknown', 'cpp_cleanup_unknown'}


def run_smoke(output):
    output = checked_path(output)
    if output.exists() or not output.parent.is_dir():
        raise ValueError('new output directory with existing parent required')
    output.mkdir()
    source = output/'source'
    source.mkdir()
    fixture_root = Path(__file__).resolve().parents[1]/'tests/fixtures'
    names = ['compiler_memory_cases.c','compiler_memory_cases.cpp']
    before = {}
    for name in names:
        shutil.copyfile(fixture_root/name, source/name)
        before[name] = hashlib.sha256((source/name).read_bytes()).hexdigest()
    def git(*args):
        return subprocess.check_output(['git','-C',str(source),*args],text=True,stderr=subprocess.STDOUT).strip()
    git('init','-q')
    git('add','--',*names)
    git('-c','user.name=WildTrace synthetic fixture','-c','user.email=fixture@invalid.local',
        '-c','commit.gpgsign=false','commit','-qm','Static-only compiler contrast fixture')
    profile = {'schema':'engine-profile-0.1','component':'synthetic-compiler-core',
        'source_repositories':{'.':git('rev-parse','HEAD')},'source_files':names,
        'include_dirs':[],'defines':[],'extra_compile_args':[],'engines':['clang-static-analyzer']}
    profile_path = output/'profile.json'
    exclusive_json(profile_path,profile)
    result = run_compiler_profile(source,profile_path)
    exclusive_json(output/'result.json',result)
    validate_result(result)
    if result['status'] != 'completed':
        raise ValueError('real compiler failed: '+json.dumps(result['input_errors']))
    observed = {f['evidence']['function']['name']:f['cwe_candidate'] for f in result['findings']}
    functions = {f['name'] for u in result['compiler_facts'] for f in u['functions']}
    if observed != POSITIVE or not (set(POSITIVE)|NEGATIVE|UNKNOWN).issubset(functions):
        raise ValueError('compiler contrast mismatch: '+json.dumps({'observed':observed,'functions':sorted(functions)}))
    if any(n in observed for n in NEGATIVE|UNKNOWN):
        raise ValueError('a control or unknown input became a numeric violation')
    after = {name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in names}
    if before != after or git('status','--porcelain'):
        raise ValueError('synthetic source changed during static analysis')
    report = build_audit_report(result)
    validate_report_against_result(report,result)
    exclusive_json(output/'report.candidate.json',report)
    acceptance = {'status':'passed','compiler_version':result['compiler_version']['version'],
        'positive_cases':len(POSITIVE),'negative_controls':len(NEGATIVE),'unknown_controls':len(UNKNOWN),
        'functions':len(functions),'observed':observed,'files_scanned':result['scan']['files_scanned'],
        'target_executed':False,'confirmed_real_vulnerabilities':0,
        'limitations':['Development-used contrast cases, not a real-world accuracy estimate.',
                       'Actual syntax/AST compiler execution; no fixture executable was built or run.']}
    exclusive_json(output/'acceptance.json',acceptance)
    print(json.dumps(acceptance,ensure_ascii=False),flush=True)
    return acceptance


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        run_smoke(args.output)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print('COMPILER_SMOKE_FAILED '+str(exc),flush=True)
        raise SystemExit(1)
