import json
import unittest
from ohvul.workflow.fsm import WorkflowCheckpoint
from ohvul.verification_link import make_checkpoint_link, validate_checkpoint_link


class CheckpointLinkTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(schema='0.1', case_id='synthetic', verdict='undetermined',
                           review_required=True, reproducible=True)
        self.checkpoint = WorkflowCheckpoint('task', state='local_verification')
        self.raw = json.dumps(self.checkpoint.to_dict()).encode()

    def test_round_trip_and_exact_bytes(self):
        link = make_checkpoint_link(self.raw, self.record)
        self.assertTrue(validate_checkpoint_link(link, self.record, self.raw))
        with self.assertRaisesRegex(ValueError, 'bytes mismatch'):
            validate_checkpoint_link(link, self.record, self.raw + b'\n')

    def test_forged_link_task_and_hash_are_rejected(self):
        link = make_checkpoint_link(self.raw, self.record)
        for change in ({'task_id': 'other'}, {'checkpoint_sha256': '0' * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_checkpoint_link(dict(link, **change), self.record, self.raw)

    def test_wrong_state_schema_and_record_rejected(self):
        for state in ('intake', 'static_scan', 'blocked', 'completed'):
            data = dict(self.checkpoint.to_dict(), state=state)
            with self.subTest(state=state), self.assertRaises(ValueError):
                make_checkpoint_link(json.dumps(data).encode(), self.record)
        with self.assertRaises(ValueError):
            make_checkpoint_link(b'{}', self.record)
        with self.assertRaises(ValueError):
            make_checkpoint_link(self.raw, dict(self.record, verdict='confirmed'))
