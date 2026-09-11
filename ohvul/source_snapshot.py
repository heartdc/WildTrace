from pathlib import Path
import hashlib, json

def source_snapshot(root: Path) -> str:
    root=root.resolve(); entries=[]
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink(): continue
        rel=path.relative_to(root).as_posix(); data=path.read_bytes()
        entries.append({'path':rel,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    payload=json.dumps(entries,sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(payload).hexdigest()
