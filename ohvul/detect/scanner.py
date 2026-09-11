from __future__ import annotations
import hashlib, pathlib, re
from datetime import datetime, timezone
from ohvul.domain.evidence import make_bundle

EXTENSIONS={".c",".h",".cc",".cpp",".cxx",".hpp"}
RULES=[("CWE-190","integer-overflow-length","Possible integer arithmetic used as a memory-size argument",re.compile(r"\b(?:malloc|calloc|realloc|memcpy|memmove)\s*\([^;\n]*[+*]\s*[^;\n]*\)")),("CWE-476","null-dereference","Possible dereference of a pointer after a nullable-returning call",re.compile(r"(?:->|\*)\s*[A-Za-z_]\w*")),("CWE-122","heap-buffer-overflow","Use of a memory-copy API requires manual boundary review",re.compile(r"\b(?:strcpy|strcat|sprintf|memcpy|memmove)\s*\("))]
def _line_hash(line): return hashlib.sha256(line.strip().encode()).hexdigest()[:16]
def scan_path(root, relative_files=None):
 root=pathlib.Path(root).resolve(); findings=[]; bundles=[]; files=0
 allowed = set(relative_files) if relative_files is not None else None
 for f in root.rglob("*"):
  if not f.is_file() or f.suffix.lower() not in EXTENSIONS: continue
  if allowed is not None and f.relative_to(root).as_posix() not in allowed: continue
  files+=1
  try: lines=f.read_text(encoding="utf-8",errors="replace").splitlines()
  except OSError: continue
  for no,line in enumerate(lines,1):
   if "ohvul:ignore" in line: continue
   for cwe,rule,desc,rx in RULES:
    if cwe == "CWE-476" and any(api + "(" in line for api in ("strcpy", "strcat", "sprintf", "memcpy", "memmove")): continue
    if rx.search(line):
     ev={"code":line.strip(),"line_hash":_line_hash(line)}; b=make_bundle("static_scan",{"root":str(root),"file":str(f.relative_to(root)),"line":no},evidence=ev)
     bundles.append(b.to_dict()); findings.append({"alert_id":f"AL-{len(findings)+1:06d}","source":"builtin_rule","cwe_candidate":cwe,"rule":rule,"description":desc,"location":{"file":str(f.relative_to(root)),"line":no},"evidence":ev,"evidence_id":b.evidence_id,"status":"candidate"})
 return {"schema_version":"0.3","scan":{"root":str(root),"files_scanned":files,"completed_at":datetime.now(timezone.utc).isoformat()},"findings":findings,"evidence_bundles":bundles,"safety":{"local_only":True,"no_execution":True,"no_network":True}}







