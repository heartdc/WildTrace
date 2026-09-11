import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from ohvul.domain.evidence import digest


class SealRecordCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'archive.json'
        self.output = self.root / 'seal.json'
        events = [{'event': 'begin', 'task_id': 'fixture'}]
        self.data = {'archive_schema': '0.1', 'task_id': 'fixture', 'events': events,
                     'event_filter': [], 'since': None, 'events_sha256': digest(events)}
        self.archive.write_text(json.dumps(self.data), encoding='utf-8')

    def run_record(self, output=None):
        return subprocess.run([sys.executable, '-m', 'ohvul.archive_seal_record',
            str(self.archive), str(output or self.output), '--operator', 'fixture-user',
            '--reason', 'synthetic test'], capture_output=True, text=True)

    def test_create_verify_and_preserve_archive(self):
        before = self.archive.read_bytes()
        result = self.run_record()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        check = subprocess.run([sys.executable, '-m', 'ohvul.archive_seal_verify',
            str(self.output), str(self.archive)], capture_output=True)
        self.assertEqual(check.returncode, 0)
        self.assertEqual(self.archive.read_bytes(), before)
        original_seal = self.output.read_bytes()
        self.assertEqual(self.run_record().returncode, 1)
        self.assertEqual(self.output.read_bytes(), original_seal)

    def test_cannot_overwrite_source(self):
        original = self.archive.read_bytes()
        result = self.run_record(self.archive)
        self.assertEqual(result.returncode, 1)
        self.assertIn('must differ', result.stdout)
        self.assertEqual(original, self.archive.read_bytes())

    def test_invalid_archive_produces_no_marker(self):
        for invalid in ([], {**self.data, 'events_sha256': 'bad'},
                        {**self.data, 'events': [None]}):
            with self.subTest(invalid=invalid):
                self.archive.write_text(json.dumps(invalid), encoding='utf-8')
                result = self.run_record()
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(self.output.exists())
