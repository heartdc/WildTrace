import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul.source_snapshot import source_snapshot


class SourceSnapshotTests(unittest.TestCase):
    def test_snapshot_matches_legacy_digest_and_changes_with_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'b.c').write_bytes(b'b')
            (root / 'a.c').write_bytes(b'a')
            entries = [{'path': name, 'size': 1, 'sha256': hashlib.sha256(data).hexdigest()}
                       for name, data in [('a.c', b'a'), ('b.c', b'b')]]
            expected = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            self.assertEqual(source_snapshot(root), expected)
            (root / 'a.c').write_bytes(b'changed')
            self.assertNotEqual(source_snapshot(root), expected)

    def test_symlinks_are_not_included(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / 'real.c'
            real.write_text('x')
            link = root / 'link.c'
            try:
                link.symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest('symlink unavailable')
            only = source_snapshot(root)
            link.unlink()
            self.assertEqual(only, source_snapshot(root))

    def test_whole_tree_budget_rejects_before_opening_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'large.bin').write_bytes(b'x' * 32)
            with patch.object(Path, 'open', side_effect=AssertionError('must not read oversized file')):
                with self.assertRaisesRegex(ValueError, 'byte budget'):
                    source_snapshot(root, max_bytes=8)

    def test_file_count_budget_stops_during_enumeration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('a.c', 'b.c', 'c.c'):
                (root / name).write_bytes(b'x')
            scandir = os.scandir
            @contextmanager
            def bounded_entries(path):
                with scandir(path) as entries:
                    def observed():
                        for index, entry in enumerate(entries):
                            if index >= 2:
                                self.fail('enumeration continued after file budget was exceeded')
                            yield entry
                    yield observed()
            with patch('ohvul.source_snapshot.os.scandir', side_effect=bounded_entries), \
                 patch.object(Path, 'open', side_effect=AssertionError('must not start hashing')):
                with self.assertRaisesRegex(ValueError, 'file budget'):
                    source_snapshot(root, max_files=1)

    def test_enumeration_budget_also_bounds_empty_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('a', 'b', 'c'):
                (root / name).mkdir()
            with self.assertRaisesRegex(ValueError, 'enumeration budget'):
                source_snapshot(root, max_entries=2)

    def test_files_are_streamed_without_read_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'large.bin').write_bytes(b'x' * (2 * 1024 * 1024 + 17))
            before = source_snapshot(root)
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('unbounded read')):
                self.assertEqual(source_snapshot(root), before)


if __name__ == '__main__':
    unittest.main()
