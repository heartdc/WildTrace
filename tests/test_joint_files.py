import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ohvul.verification_link import make_checkpoint_link, validate_joint_files
from ohvul.workflow.fsm import WorkflowCheckpoint, load_checkpoint


class JointFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.cp, self.result, self.harness = [root / n for n in ('cp.json', 'scan.json', 'harness.json')]
        self.scan = {'schema_version': '0.3', 'workflow': {'task_id': 'synthetic-task'},
                     'findings': [], 'evidence_bundles': []}
        self.record = dict(schema='0.1', case_id='synthetic', verdict='undetermined',
                           review_required=True, reproducible=True)
        self.write_chain(self.scan)

    def write_chain(self, scan):
        raw = json.dumps(scan).encode('utf-8')
        self.result.write_bytes(raw)
        checkpoint = WorkflowCheckpoint('synthetic-task', state='local_verification',
                                        result_sha256=hashlib.sha256(raw).hexdigest())
        cp_raw = json.dumps(checkpoint.to_dict()).encode('utf-8')
        self.cp.write_bytes(cp_raw)
        self.harness.write_text(json.dumps({'record': self.record,
            'link': make_checkpoint_link(cp_raw, self.record)}), encoding='utf-8')

    def test_each_result_is_read_once(self):
        original = Path.read_bytes
        reads = []
        def read_once(path):
            reads.append(path)
            return original(path)
        with patch.object(Path, 'read_bytes', read_once):
            self.assertTrue(validate_joint_files(self.cp, self.result, self.harness))
        self.assertEqual(reads.count(self.result), 1)

    def test_transition_requires_matching_verified_files(self):
        checkpoint = load_checkpoint(self.cp)
        checkpoint.transition('triage', verification_files=(self.cp, self.result, self.harness))
        self.assertEqual(checkpoint.state, 'triage')

    def test_transition_rejects_stale_checkpoint_without_mutation(self):
        checkpoint = load_checkpoint(self.cp)
        checkpoint.retry_count += 1
        before = checkpoint.to_dict()
        with self.assertRaisesRegex(ValueError, 'differs from current'):
            checkpoint.transition('triage', verification_files=(self.cp, self.result, self.harness))
        self.assertEqual(checkpoint.to_dict(), before)

    def test_transition_rejects_changed_file_without_mutation(self):
        checkpoint = load_checkpoint(self.cp)
        before = checkpoint.to_dict()
        self.result.write_bytes(self.result.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'bytes mismatch'):
            checkpoint.transition('triage', verification_files=(self.cp, self.result, self.harness))
        self.assertEqual(checkpoint.to_dict(), before)

    def test_changed_result_bytes_rejected(self):
        self.result.write_bytes(self.result.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'bytes mismatch'):
            validate_joint_files(self.cp, self.result, self.harness)

    def test_wrong_task_and_missing_evidence_rejected(self):
        for scan in (dict(self.scan, workflow={'task_id': 'other'}),
                     dict(self.scan, findings=[{'evidence_id': 'missing'}])):
            self.write_chain(scan)
            with self.assertRaises(ValueError):
                validate_joint_files(self.cp, self.result, self.harness)

    def test_cli_accepts_chain_and_rejects_malformed_envelope(self):
        command = [sys.executable, '-m', 'ohvul.verify_joint',
                   str(self.cp), str(self.result), str(self.harness)]
        success = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertIn('no vulnerability verdict', success.stdout)
        self.harness.write_text('[]', encoding='utf-8')
        failure = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(failure.returncode, 1)
        self.assertIn('INVALID:', failure.stdout)
        self.assertNotIn('Traceback', failure.stderr)

    def test_non_object_scan_and_null_workflow_rejected(self):
        for scan in ([], dict(self.scan, workflow=None)):
            self.write_chain(scan)
            with self.assertRaisesRegex(ValueError, 'workflow'):
                validate_joint_files(self.cp, self.result, self.harness)
