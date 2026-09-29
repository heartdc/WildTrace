"""Component-registration injector for selective OH checkouts (2026-09-29).

Root-target gen on a selectively synced tree fails on parts that exist in
the product but not in this checkout. This tool iterates gn gen and, per
failure, resolves the missing component/innerapi by (1) an existing copy
elsewhere in the WSL tree, (2) the Windows full tree, (3) a rust-crate
name mapping - then copies the source in and injects the registration
(components.json + third_party_allow_list.json). Known companions (set in
the out dir's args.gn): taihe_template_bypass = true,
runtime_core_enable_codegen = false. Blocked-without-network remainder:
taihe_ffi_gen / asmjit / zydis subrepos and generated rust BUILD.gn for
the rust-openssl workspace (see TIER_EFG_BUILD_STATUS_20260929.md).

Usage: python3 component_inject.py <outdirname> <//root:target>
"""
import json, re, subprocess, sys
from pathlib import Path
T = Path('/home/airgap/oh-real-20260925')
FULL = Path('/mnt/c/Projects/OpenHarmony')
O = T / 'out' / sys.argv[1]
ROOT_TARGET = sys.argv[2]
GN = T / 'prebuilts/build-tools/linux-x86/bin/gn'
CFG = O / 'build_configs/parts_info/components.json'
ALLOW = T / 'build/third_party_allow_list.json'

def find_bundle(component):
    bases = ['third_party', 'base', 'commonlibrary', 'developtools', 'foundation']
    cands = [component, component.replace('_', '-')]
    if component.startswith('rust_'):
        bases.insert(0, 'third_party/rust/crates')
        cands.insert(0, component[len('rust_'):])
    for root in (T, FULL):
        for base in bases:
            for name in cands:
                for marker in ('bundle.json', 'BUILD.gn'):
                    f = root / base / name / marker
                    if f.is_file():
                        return base, name
    return None

def ensure_source(base, name):
    dst = T / base / name
    if (dst / 'BUILD.gn').is_file():
        return str(dst.relative_to(T))
    src = FULL / base / name
    dst.mkdir(parents=True, exist_ok=True)
    subprocess.run(['bash', '-c', f'(cd "{src}" && tar --exclude=.git -cf - .) | (cd "{dst}" && tar xf -)'], check=True)
    return str(dst.relative_to(T))

comps = json.load(open(CFG))
allow = json.load(open(ALLOW))
for it in range(1, 26):
    r = subprocess.run([str(GN), 'gen', str(O), f'--root-target={ROOT_TARGET}'], cwd=T,
                       capture_output=True, text=True)
    log = r.stdout + r.stderr
    if r.returncode == 0:
        print(f'GEN_OK iter {it}'); break
    m = re.search(r'OHOS component : \(([\w-]+)\) not found', log)
    mi = re.search(r'OHOS innerapi: \(([\w.-]+)\) not found for component \(([\w-]+)\)', log)
    if mi:
        inner, comp = mi.group(1), mi.group(2)
        entry = comps.get(comp)
        if not entry:
            found = find_bundle(comp)
            if not found:
                print(f'INNERAPI_NO_COMPONENT_SRC: {comp}'); break
            base, name = found
            rel = ensure_source(base, name)
            bundle = json.load(open(FULL / base / name / 'bundle.json'))
            entry = {'deps_components': [], 'innerapis': [], 'path': rel,
                     'subsystem': bundle.get('component', {}).get('subsystem', 'thirdparty'), 'variants': []}
            comps[comp] = entry
        names = [i['name'] for i in entry['innerapis']]
        if inner not in names:
            label_dir = entry['path']
            root = T / entry['path']
            for bg in root.rglob('BUILD.gn'):
                try:
                    txt = bg.read_text(errors='ignore')
                except OSError:
                    continue
                if f'("{inner}")' in txt:
                    label_dir = bg.parent.relative_to(T).as_posix()
                    break
            entry['innerapis'].append({'label': f"//{label_dir}:{inner}", 'name': inner})
            json.dump(comps, open(CFG, 'w'), indent=1)
            print(f'iter {it}: innerapi {comp}:{inner} injected')
            continue
    if not m and not mi:
        print('NON_COMPONENT_ERROR')
        mm = re.search(r'ERROR at.{0,400}', log, re.S)
        print(mm.group(0) if mm else log[-400:])
        break
    if not m:
        print('INNERAPI loop exhausted'); break
    comp = m.group(1)
    dep = re.search(r'"%s:([\w.-]+)"' % comp, log)
    target_name = dep.group(1) if dep else comp
    found = find_bundle(comp)
    if not found:
        print(f'NOT_IN_FULL_TREE: {comp}'); break
    base, name = found
    rel = ensure_source(base, name)
    bp = T / base / name / 'bundle.json'
    if not bp.is_file():
        bp = FULL / base / name / 'bundle.json'
    subsystem = 'thirdparty'
    try:
        subsystem = json.load(open(bp)).get('component', {}).get('subsystem', 'thirdparty')
    except Exception:
        pass
    comps[comp] = {'deps_components': [], 'innerapis': [
        {'label': f'//{rel}:{target_name}', 'name': target_name}],
        'path': rel, 'subsystem': subsystem, 'variants': []}
    json.dump(comps, open(CFG, 'w'), indent=1)
    if comp not in allow:
        allow.append(comp); json.dump(allow, open(ALLOW, 'w'), indent=1)
    print(f'iter {it}: injected {comp} ({rel}:{target_name})')
