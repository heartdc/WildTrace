#!/usr/bin/env python3
"""Sweep duplicate ninja rules after `gn gen` on the OpenHarmony tree.

Background: `gn gen --root-target=...` on the OH tree emits a ninja graph with
duplicate output rules (self-stamp edges, cross-toolchain collisions, and
same-file stamp-vs-real pairs inside root toolchain.ninja). `ninja -t targets
all` does NOT report the same-file class (root toolchain.ninja); only a real
build does. Therefore the probe here is a DRY RUN of the actual target
(`ninja -n <target>`), which parses the graph exactly like a real build.

Fix rules applied per duplicate target (first match wins), matching what was
validated on the official full tree (see docs/analysis/
UDMF_REAL_LIBRARY_CONFIRM_20261009.md, "environment and build" section):

  1. self-stamp     : `build T: stamp T`          -> delete that edge
  2. identical dedup: N byte-identical rules      -> delete all but the first
  3. cross drop     : same output in root toolchain.ninja and elsewhere
                                                      -> keep root, drop others
  4. stamp-vs-real  : same file holds a stamp edge and a real action
                                                      -> drop the stamp edge

Only ninja build edges are deleted; no source or product content is touched.

Usage:
    python3 sweep_v3.py <oh_root> <out_dir> <ninja_target>

    oh_root      OH tree root (contains prebuilts/build-tools/linux-x86/bin/ninja)
    out_dir      build output dir (e.g. out/x86_64_virt)
    ninja_target target label exactly as passed to ninja (e.g.
                 distributeddatamgr/udmf/libcj_unified_data_channel_ffi.z.so)
"""
import os, re, subprocess, sys

if len(sys.argv) != 4:
    sys.exit(__doc__)
OH_ROOT, O, TARGET = sys.argv[1], os.path.abspath(sys.argv[2]), sys.argv[3]
NINJA = os.path.join(OH_ROOT, 'prebuilts', 'build-tools', 'linux-x86', 'bin', 'ninja')
if not os.path.isfile(NINJA):
    sys.exit(f'ninja not found: {NINJA}')

def probe():
    r = subprocess.run([NINJA, '-C', O, '-n', TARGET],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    return r.returncode, r.stderr

def find_rules(target):
    hits = []
    for root, _, files in os.walk(O):
        for f in files:
            if not f.endswith('.ninja'):
                continue
            p = os.path.join(root, f)
            try:
                with open(p, errors='replace') as fh:
                    for i, l in enumerate(fh):
                        if l.startswith(f'build {target}:'):
                            hits.append((p, i, l.rstrip('\n')))
            except OSError:
                pass
    return hits

def drop_line(p, i):
    lines = open(p, errors='replace').read().splitlines()
    del lines[i]
    open(p, 'w').write('\n'.join(lines) + '\n')

for it in range(1, 4000):
    rc, err = probe()
    m = re.search(r'ninja: error: ([^:\s]+(?:\.ninja)?):(\d+): multiple rules generate (\S+)', err)
    if not m:
        print(f'GRAPH_CLEAN iter {it}' if rc == 0 else f'OTHER_PROBE: {err[:200]}')
        break
    target = m.group(3)
    rules = find_rules(target)
    if len(rules) < 2:
        print(f'RULES_NOT_FOUND {target}'); break
    selfs = [h for h in rules if re.match(rf'build {re.escape(target)}: (?:clang_x64_)?stamp {re.escape(target)}\s*$', h[2])]
    if selfs:
        p, i, _ = selfs[0]
        drop_line(p, i)
        print(f'iter {it}: self-stamp {os.path.relpath(p, O)}:{i+1}', flush=True)
        continue
    if len(set(h[2] for h in rules)) == 1:
        p, i, _ = rules[0]
        drop_line(p, i)
        print(f'iter {it}: identical dedup {os.path.relpath(p, O)}:{i+1}', flush=True)
        continue
    def canonical(h):
        rel = os.path.relpath(h[0], O)
        return rel == 'toolchain.ninja' or '/m133/' in rel
    keep = [h for h in rules if canonical(h)]
    others = [h for h in rules if not canonical(h)]
    if keep and others:
        for p, i, _ in sorted(others, key=lambda h: (h[0], -h[1])):
            drop_line(p, i)
            print(f'iter {it}: cross drop {os.path.relpath(p, O)}:{i+1}', flush=True)
        continue
    files = {}
    for p, i, l in rules:
        files.setdefault(p, []).append((i, l))
    done = False
    for p, lst in files.items():
        if len(lst) == 2:
            real = [x for x in lst if not re.match(r'build \S+: (?:clang_x64_)?stamp ', x[1])]
            stamps = [x for x in lst if re.match(r'build \S+: (?:clang_x64_)?stamp ', x[1])]
            if real and stamps:
                drop_line(p, stamps[0][0])
                print(f'iter {it}: same-file stamp-vs-real drop {os.path.relpath(p, O)}:{stamps[0][0]+1}', flush=True)
                done = True
                break
    if done:
        continue
    print(f'UNHANDLED {target}: {len(rules)}')
    for h in rules[:3]:
        print('  ', h[2][:130])
    break
