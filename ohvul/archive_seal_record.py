"""Create an independent logical seal marker; no signatures or permission changes."""
import argparse
import json
import os
from pathlib import Path
from .journal_archive_verify import validate_archive
from .report import create_seal, validate_seal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--operator', required=True)
    parser.add_argument('--reason', required=True)
    args = parser.parse_args()
    try:
        if args.archive.resolve() == args.output.resolve():
            raise ValueError('seal output must differ from source archive')
        archive = json.loads(args.archive.read_text(encoding='utf-8-sig'))
        validate_archive(archive)
        marker = create_seal(archive, args.operator, args.reason)
        validate_seal(marker, archive)
        payload = json.dumps(marker, ensure_ascii=False, indent=2) + '\n'
        # Exclusive create rejects existing files, hard links and dangling symlinks.
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError, TypeError) as exc:
        print(f'INVALID: {exc}')
        return 1
    print('OK: logical seal marker created; no identity authentication or permission changes')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
