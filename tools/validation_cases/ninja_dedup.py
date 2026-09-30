"""Ninja duplicate-output sweeper for generated graphs on selective checkouts.

Handles two safe classes: identical duplicate build rules (dedup) and
self-referential stamp edges (drop). Reports anything else (e.g. genuine
cross-toolchain collisions) without touching it. Usage:
python3 ninja_dedup.py <outdirname>
"""
import re, subprocess, sys, os
O = '/home/airgap/oh-real-20260925/out/' + sys.argv[1]
NINJA = '/home/airgap/oh-real-20260925/prebuilts/build-tools/linux-x86/bin/ninja'
for it in range(1, 80):
    r = subprocess.run([NINJA, '-C', '.', '-t', 'targets', 'all'], cwd=O,
                       capture_output=True, text=True)
    m = re.search(r'ninja: error: ([^:]+):(\d+): multiple rules generate (\S+)', r.stderr + r.stdout)
    if not m:
        print(f'GRAPH_CLEAN iter {it}' if r.returncode == 0 else f'OTHER_ERROR iter {it}: {(r.stderr or r.stdout)[:200]}')
        break
    rel, line_no, target = m.group(1), int(m.group(2)), m.group(3)
    path = os.path.join(O, rel)
    if not os.path.isfile(path):
        print(f'FILE_MISSING: {rel}'); break
    lines = open(path, errors='replace').read().splitlines()
    self_idx = [i for i, l in enumerate(lines) if l == f'build {target}: stamp {target}']
    if self_idx:
        del lines[self_idx[0]]
        open(path, 'w').write('\n'.join(lines) + '\n')
        print(f'iter {it}: removed self-stamp in {rel}:{self_idx[0]+1}')
        continue
    idx = [i for i, l in enumerate(lines) if l.startswith(f'build {target}:')]
    if len(idx) == 2 and lines[idx[0]] == lines[idx[1]]:
        del lines[idx[0]]
        open(path, 'w').write('\n'.join(lines) + '\n')
        print(f'iter {it}: dedup identical rule in {rel}:{idx[0]+1}')
        continue
    print(f'UNHANDLED in {rel} for {target}: {len(idx)} rules')
    for i in idx[:3]:
        print('  ', lines[i][:160])
    break
