"""Versioned local vulnerability knowledge-base validation; no network access."""
import hashlib, json, re
from pathlib import Path

def load_records(path):
    data=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data, dict) or data.get('schema') != '0.1' or not isinstance(data.get('records'), list): raise ValueError('invalid knowledge base')
    records=[]; seen=set()
    for record in data['records']:
        required={'id','cwe','summary','component','affected_versions','fixed_versions','source'}
        if not isinstance(record,dict) or not required.issubset(record) or not isinstance(record['id'],str) or record['id'] in seen: raise ValueError('invalid knowledge record')
        if any(not isinstance(record[k], str) or not record[k].strip() for k in ('summary','component','source')): raise ValueError('invalid knowledge text fields')
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', record['id']): raise ValueError('invalid vulnerability id')
        if not isinstance(record['cwe'],list) or any(not re.fullmatch(r'CWE-[1-9]\d*', str(x)) for x in record['cwe']): raise ValueError('invalid CWE')
        if not all(isinstance(record[k],list) and all(isinstance(x,str) for x in record[k]) for k in ('affected_versions','fixed_versions')): raise ValueError('invalid version lists')
        seen.add(record['id']); records.append(record)
    return {'schema':'0.1','records':records,'records_sha256':hashlib.sha256(json.dumps(records,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

def match_records(database, component, version):
    if not isinstance(database, dict) or not isinstance(component, str) or not isinstance(version, str): raise ValueError('invalid match input')
    candidates=[r for r in database.get('records', []) if r.get('component') == component]
    def project(r, level):
        return {'id':r['id'],'cwe':r['cwe'],'match_level':level,'source':r['source'],'knowledge_base_sha256':database.get('records_sha256'),'source_record_sha256':hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
    exact=[project(r,'exact') for r in candidates if version in r.get('affected_versions', [])]
    if exact: return exact
    return [project(r,'unresolved') for r in candidates]
