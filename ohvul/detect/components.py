from __future__ import annotations
import pathlib, re

VERSION_PATTERNS=(
 re.compile(r'(?i)\b(?:version|ver)\s*[:=]\s*["\']?([0-9]+(?:\.[0-9A-Za-z_-]+)+)'),
 re.compile(r'(?i)#\s*define\s+[A-Z0-9_]*(?:VERSION|VER)[A-Z0-9_]*\s+["\']?([0-9]+(?:\.[0-9A-Za-z_-]+)+)'),
)

def identify_components(root: pathlib.Path)->list[dict]:
 root=root.resolve(); out=[]; seen=set()
 for marker in ("README.md","README","BUILD.gn","CMakeLists.txt","package.json"):
  for f in root.rglob(marker):
   rel=f.parent.relative_to(root).as_posix() or "."
   key=str(f.parent.resolve()).lower()
   if key in seen: continue
   seen.add(key); version=None; source=None
   try: text=f.read_text(encoding="utf-8",errors="replace")[:200_000]
   except OSError: text=""
   for rx in VERSION_PATTERNS:
    m=rx.search(text)
    if m: version=m.group(1); source=f"{f.relative_to(root).as_posix()}"; break
   out.append({"name":f.parent.name or root.name,"path":rel,"version":version,"version_source":source,"marker":marker})
 return sorted(out,key=lambda x:x["path"])
