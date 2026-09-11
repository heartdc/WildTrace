"""Optional runtime LLM adapter; key is read only from environment."""
import json, os, urllib.request

def draft_analysis(context, *, base_url='https://www.oslovelace.com/v1', model='grok-4.6', timeout=30):
    key = os.environ.get('OSLOVELACE_API_KEY')
    if not key:
        raise RuntimeError('OSLOVELACE_API_KEY is not configured')
    payload = {'model': model, 'messages': [{'role':'user', 'content': json.dumps({'task':'analyze candidate evidence; do not decide vulnerability', 'context':context}, ensure_ascii=False)}], 'max_tokens': 512}
    request = urllib.request.Request(base_url.rstrip('/') + '/chat/completions', data=json.dumps(payload).encode(), headers={'Authorization':'Bearer '+key, 'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data=json.loads(response.read().decode())
    return {'model': data.get('model', model), 'draft': data['choices'][0]['message']['content'], 'final_verdict': 'undetermined'}
