"""Read-only validation of an exported audit journal archive."""
import argparse
import json
from pathlib import Path
from ohvul.domain.evidence import digest

EVENTS = {'begin', 'result', 'checkpoint', 'review_batch', 'commit', 'abort'}


def validate_archive(data):
    required = {'archive_schema', 'task_id', 'events', 'event_filter', 'since', 'events_sha256'}
    if not isinstance(data, dict) or set(data) != required or data['archive_schema'] != '0.1':
        raise ValueError('invalid archive schema')
    if not isinstance(data['task_id'], str) or not data['task_id'].strip() or not isinstance(data['events'], list):
        raise ValueError('invalid archive task or events')
    filters = data['event_filter']
    if not isinstance(filters, list) or any(not isinstance(x, str) or x not in EVENTS for x in filters):
        raise ValueError('invalid event filter')
    for event in data['events']:
        if not isinstance(event, dict) or event.get('task_id') != data['task_id']:
            raise ValueError('archive event task mismatch')
        if not isinstance(event.get('event'), str) or event['event'] not in EVENTS:
            raise ValueError('invalid archive event')
        if filters and event['event'] not in filters:
            raise ValueError('archive event violates filter')
    if data['events_sha256'] != digest(data['events']):
        raise ValueError('archive event digest mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    try:
        validate_archive(json.loads(args.archive.read_text(encoding='utf-8-sig')))
    except (OSError, ValueError, TypeError) as exc:
        print(f'INVALID: {exc}')
        return 1
    print('OK: archive is internally consistent; source journal is not modified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
