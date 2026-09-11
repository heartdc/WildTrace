from datetime import datetime, timezone
from ohvul.domain.evidence import digest

def create_seal(archive, operator, reason):
 if not isinstance(operator,str) or not operator.strip() or not isinstance(reason,str) or not reason.strip(): raise ValueError('operator and reason required')
 return {'seal_schema':'0.1','archive_sha256':digest(archive),'operator':operator,'reason':reason,'sealed_at':datetime.now(timezone.utc).isoformat(),'logical_state':'sealed'}

def validate_seal(seal,archive):
 if set(seal)!={'seal_schema','archive_sha256','operator','reason','sealed_at','logical_state'} or seal.get('seal_schema')!='0.1' or seal.get('logical_state')!='sealed': raise ValueError('invalid seal')
 if seal.get('archive_sha256')!=digest(archive): raise ValueError('seal archive mismatch')
