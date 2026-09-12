"""Validation for fixed local Git analysis scopes; no network access."""
from pathlib import Path
import re
import subprocess

def validate_scope(scope):
    required={'source_root','revision','branch','since','until','components'}
    if not isinstance(scope,dict) or set(scope) != required: raise ValueError('invalid scope fields')
    root=Path(scope['source_root'])
    if not root.is_absolute() or not root.is_dir(): raise ValueError('source_root must be an existing local directory')
    for field in ('revision','branch'):
        value=scope[field]
        if not isinstance(value,str) or not value.strip() or '://' in value or re.search(r'[\x00-\x1f]',value): raise ValueError(f'invalid local git {field}')
    for field in ('since','until'):
        if not isinstance(scope[field],str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',scope[field]): raise ValueError(f'invalid date: {field}')
    if scope['since'] > scope['until']: raise ValueError('date range is reversed')
    if not isinstance(scope['components'],list) or not scope['components'] or any(not isinstance(x,str) or not x.strip() for x in scope['components']): raise ValueError('components must be nonempty strings')
    return {'source_root':str(root.resolve()),'revision':scope['revision'],'branch':scope['branch'],'since':scope['since'],'until':scope['until'],'components':list(dict.fromkeys(scope['components']))}

def inspect_revision(scope):
    normalized=validate_scope(scope); root=normalized['source_root']
    def git(*args):
        try: return subprocess.run(['git','-C',root,*args],check=True,capture_output=True,text=True,timeout=15).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc: raise ValueError('local git inspection failed') from exc
    commit=git('rev-parse','--verify',normalized['revision']+'^{commit}')
    parents=git('rev-list','--parents','-n','1',commit).split()[1:]
    parent=parents[0] if parents else None
    changed=git('diff-tree','--no-commit-id','--name-only','-r',commit).splitlines()
    observed_branch=git('branch','--show-current')
    record={'schema':'0.1','scope':normalized,'commit':commit,'parent':parent,'observed_branch':observed_branch,'changed_files':changed,'local_only':True}
    import hashlib, json
    record['scope_sha256']=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return record
