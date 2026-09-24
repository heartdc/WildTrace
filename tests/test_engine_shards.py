import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ohvul.engine_shards import scan_engine_shard
from ohvul.engine_shards import scan_engine_manifest
from ohvul.source_snapshot import source_snapshot


def _make_cache_canary(root, count=300):
    cache = root / '.cache-canary'
    cache.mkdir()
    for index in range(count):
        (cache / f'blob-{index:04d}').write_text('x' * 64)
    return cache


class _HashRecorder:
    def __init__(self):
        self.original = None
        self.paths = []

    def __call__(self, path):
        self.paths.append(Path(path).name)
        return self.original(path)

    @property
    def canary_visits(self):
        return [name for name in self.paths if name.startswith('blob-')]


class EngineShardTests(unittest.TestCase):
    def test_missing_file_is_input_error(self):
        # Audit 2026-09-23 P1-1 regression: a missing input must be reported
        # from an isolated root without hashing unrelated cache content.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_cache_canary(root)
            recorder = _HashRecorder()
            recorder.original = __import__('ohvul.source_snapshot', fromlist=['_hash_file'])._hash_file
            with patch('ohvul.source_snapshot._hash_file', recorder):
                result = scan_engine_shard(root, {'files': ['does-not-exist.c']})
            self.assertEqual(result['status'], 'input_error')
            self.assertEqual(len(result['input_errors']), 1)
            self.assertEqual(recorder.paths, [])

    def test_manifest_renumbers_engine_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('int a;')
            (root / 'b.c').write_text('int b;')
            normalized = lambda file: {'status': 'completed', 'findings': [{'location': {'file': file, 'line': 1}, 'rule': 'R', 'evidence_id': file}]}
            with patch('ohvul.engine_shards.run_wsl_clang_analyzer', side_effect=lambda source, root, **kwargs: normalized(source.name)):
                result = scan_engine_manifest(root, {'root': str(root.resolve()), 'shards': [{'files': ['a.c']}, {'files': ['b.c']}]})
            self.assertEqual([f['alert_id'] for f in result['findings']], ['AL-ENG-000001', 'AL-ENG-000002'])

    def test_single_file_request_does_not_hash_unrelated_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.c').write_text('int main;')
            _make_cache_canary(root)
            normalized = lambda file: {'status': 'completed', 'findings': []}
            recorder = _HashRecorder()
            recorder.original = __import__('ohvul.source_snapshot', fromlist=['_hash_file'])._hash_file
            with patch('ohvul.source_snapshot._hash_file', recorder), \
                 patch('ohvul.engine_shards.run_wsl_clang_analyzer',
                            side_effect=lambda source, root, **kwargs: normalized(source.name)):
                scan_engine_shard(root, {'files': ['main.c']})
            # Exactly the declared input is hashed, once before and once after the run.
            self.assertEqual(recorder.paths, ['main.c', 'main.c'])
            self.assertEqual(recorder.canary_visits, [])

    def test_manifest_snapshot_visits_are_scoped_and_bounded(self):
        # Audit 2026-09-23 P1-1 regression: the manifest performs exactly two
        # tree-level walks (publication contract, budget-bounded) regardless
        # of shard count, while per-shard snapshots stay scoped to the
        # declared inputs. Old behavior hashed the whole tree 2S+2 times.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('a.c', 'b.c', 'c.c'):
                (root / name).write_text(f'int {name[0]};')
            canary_count = 300
            _make_cache_canary(root, canary_count)
            normalized = lambda file: {'status': 'completed', 'findings': []}
            recorder = _HashRecorder()
            recorder.original = __import__('ohvul.source_snapshot', fromlist=['_hash_file'])._hash_file
            with patch('ohvul.source_snapshot._hash_file', recorder), \
                 patch('ohvul.engine_shards.run_wsl_clang_analyzer',
                            side_effect=lambda source, root, **kwargs: normalized(source.name)):
                scan_engine_manifest(root, {'root': str(root.resolve()),
                                            'shards': [{'files': ['a.c', 'b.c']}, {'files': ['c.c']}]})
            # Manifest: 2 tree walks over 303+1 files... tree = 3 declared + canary.
            # Shard scoped work: (a,b)x2 + (c)x2 = 6. Canary only from the 2
            # manifest walks: 300 canary files x 2 = 600 visits.
            self.assertEqual(len(recorder.canary_visits), 2 * canary_count)
            declared_visits = [name for name in recorder.paths if not name.startswith('blob-')]
            # 2 manifest walks (3 files each) + scoped shard work (6) = 12.
            self.assertEqual(sorted(declared_visits),
                             sorted(['a.c'] * 4 + ['b.c'] * 4 + ['c.c'] * 4))
            self.assertEqual(len(recorder.paths), 2 * canary_count + 12)


class SourceSnapshotTests(unittest.TestCase):
    def _root_with_files(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / 'a.c').write_text('int a;')
        (root / 'sub').mkdir()
        (root / 'sub' / 'b.c').write_text('int bb;')
        return root

    def test_payload_format_matches_legacy_digest(self):
        root = self._root_with_files()
        legacy = [{'path': 'a.c', 'size': 6, 'sha256': hashlib.sha256(b'int a;').hexdigest()},
                  {'path': 'sub/b.c', 'size': 7, 'sha256': hashlib.sha256(b'int bb;').hexdigest()}]
        expected = hashlib.sha256(
            json.dumps(legacy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(source_snapshot(root), expected)
        self.assertEqual(source_snapshot(root, files=['a.c', 'sub/b.c']), expected)

    def test_scoped_mode_validates_before_hashing(self):
        root = self._root_with_files()
        with self.assertRaisesRegex(ValueError, 'not an existing relative file'):
            source_snapshot(root, files=['a.c', 'missing.c'])

    def test_budget_limits_raise_explicit_errors(self):
        root = self._root_with_files()
        with self.assertRaisesRegex(ValueError, 'max_files'):
            source_snapshot(root, files=['a.c', 'sub/b.c'], max_files=1)
        with self.assertRaisesRegex(ValueError, 'max_bytes'):
            source_snapshot(root, files=['a.c', 'sub/b.c'], max_bytes=6)
        with patch('ohvul.source_snapshot.time.monotonic', side_effect=[0.0, 1000.0]):
            with self.assertRaisesRegex(ValueError, 'max_seconds'):
                source_snapshot(root, files=['a.c'], max_seconds=300)

    def test_streaming_hash_covers_large_files(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        payload = bytes(range(256)) * (8 * 1024)  # 2 MiB, spans multiple chunks
        (root / 'big.bin').write_bytes(payload)
        expected = hashlib.sha256(payload).hexdigest()
        scoped = source_snapshot(root, files=['big.bin'])
        manual = hashlib.sha256(json.dumps(
            [{'path': 'big.bin', 'size': len(payload), 'sha256': expected}],
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(scoped, manual)


if __name__ == '__main__':
    unittest.main()
