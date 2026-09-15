"""Local, synthetic regressions for recovery and publication invariants."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ohvul import cli
from ohvul.source_snapshot import source_snapshot
from ohvul.workflow.fsm import (
    MAX_RETRIES, WorkflowCheckpoint, load_checkpoint, resume_blocked,
    save_checkpoint, validate_checkpoint_data, validate_checkpoint_result,
)
from ohvul.workflow.journal import AuditJournal, latest_attempt, validate_commit


class RecoveryInvariantTests(unittest.TestCase):
    def test_direct_and_helper_recovery_share_budget_and_binding(self):
        for helper in (False, True):
            for target in ('intake', 'static_scan'):
                with self.subTest(helper=helper, target=target):
                    checkpoint = WorkflowCheckpoint(
                        'task', state='blocked', retry_count=1, last_error='failed',
                        result_sha256='a' * 64, source_snapshot_sha256='b' * 64,
                    )
                    if helper:
                        resume_blocked(checkpoint, target)
                    else:
                        checkpoint.transition(target)
                    self.assertEqual(checkpoint.state, target)
                    self.assertEqual(checkpoint.retry_count, 2)
                    self.assertIsNone(checkpoint.result_sha256)
                    self.assertIsNone(checkpoint.last_error)
                    self.assertEqual(checkpoint.source_snapshot_sha256, 'b' * 64)

    def test_exhausted_recovery_is_rejected_without_mutation(self):
        for helper in (False, True):
            for target in ('intake', 'static_scan'):
                with self.subTest(helper=helper, target=target):
                    checkpoint = WorkflowCheckpoint(
                        'task', state='blocked', retry_count=MAX_RETRIES,
                        last_error='failed', result_sha256='a' * 64,
                        source_snapshot_sha256='b' * 64,
                    )
                    before = checkpoint.to_dict()
                    with self.assertRaises(ValueError):
                        (resume_blocked(checkpoint, target) if helper
                         else checkpoint.transition(target))
                    self.assertEqual(checkpoint.to_dict(), before)

    def test_recovery_cannot_skip_verification_or_report_gates(self):
        for target in ('triage', 'report', 'human_review', 'completed'):
            with self.subTest(target=target):
                checkpoint = WorkflowCheckpoint(
                    'task', state='blocked', last_error='failed',
                    result_sha256='a' * 64,
                )
                before = checkpoint.to_dict()
                with self.assertRaises(ValueError):
                    checkpoint.transition(target)
                self.assertEqual(checkpoint.to_dict(), before)

    def test_invalid_reason_does_not_consume_recovery_budget(self):
        checkpoint = WorkflowCheckpoint('task', state='blocked', last_error='failed')
        before = checkpoint.to_dict()
        with self.assertRaises(ValueError):
            checkpoint.transition('intake', reason=object())
        self.assertEqual(checkpoint.to_dict(), before)

    def test_invalid_checkpoint_fields_are_rejected(self):
        for change in ({'retry_count': True}, {'retry_count': False},
                       {'result_sha256': 'z' * 64},
                       {'source_snapshot_sha256': '!' * 64}):
            with self.subTest(change=change):
                data = WorkflowCheckpoint('task').to_dict()
                data.update(change)
                with self.assertRaises(ValueError):
                    validate_checkpoint_data(data)

    def test_invalid_checkpoint_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checkpoint.json'
            with self.assertRaises(ValueError):
                save_checkpoint(WorkflowCheckpoint('task', retry_count=True), path)
            self.assertFalse(path.exists())


class PublicationInvariantTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.code = self.source / 'sample.c'
        self.code.write_text('void f(void) { memcpy(d, s, n); }\n', encoding='utf-8')
        self.result = self.root / 'result.json'
        self.checkpoint = self.root / 'checkpoint.json'
        self.report = self.root / 'report.json'
        self.journal = self.root / 'journal.jsonl'

    def run_cli(self, *extra):
        argv = ['ohvul.cli', str(self.source), '--output', str(self.result),
                '--checkpoint', str(self.checkpoint), '--report-output', str(self.report),
                '--journal', str(self.journal), '--task-id', 'p0-task', *extra]
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', argv), redirect_stdout(output), redirect_stderr(errors):
            try:
                cli.main()
                return 0
            except SystemExit as exc:
                return exc.code

    def assert_aborted_without_success(self):
        checkpoint = load_checkpoint(self.checkpoint)
        self.assertEqual(checkpoint.state, 'blocked')
        self.assertIsNone(checkpoint.result_sha256)
        events = latest_attempt(AuditJournal(self.journal).read(), 'p0-task')
        self.assertEqual([item['event'] for item in events], ['begin', 'abort'])
        with self.assertRaises(ValueError):
            validate_commit(AuditJournal(self.journal), 'p0-task', self.result, self.checkpoint)

    def test_both_recovery_targets_rerun_and_keep_retry_count(self):
        for target in ('intake', 'static_scan'):
            with self.subTest(target=target):
                checkpoint = WorkflowCheckpoint(
                    'p0-task', state='blocked', retry_count=1, last_error='failed',
                    result_sha256='a' * 64,
                    source_snapshot_sha256=source_snapshot(self.source),
                )
                resume_blocked(checkpoint, target)
                save_checkpoint(checkpoint, self.checkpoint, force=True)
                self.assertEqual(self.run_cli('--force'), 0)
                saved = load_checkpoint(self.checkpoint)
                self.assertEqual(saved.task_id, 'p0-task')
                self.assertEqual(saved.retry_count, 2)
                self.assertEqual(saved.state, 'static_scan')
                self.assertIsNone(json.loads(self.result.read_text())['workflow']['result_sha256'])
                self.assertEqual(saved.result_sha256, hashlib.sha256(self.result.read_bytes()).hexdigest())
                validate_commit(AuditJournal(self.journal), 'p0-task', self.result, self.checkpoint)

    def test_successful_rerun_does_not_embed_previous_result_digest(self):
        self.assertEqual(self.run_cli(), 0)
        previous = self.result.read_bytes()
        self.assertEqual(self.run_cli('--force'), 0)
        self.assertIsNone(json.loads(self.result.read_text())['workflow']['result_sha256'])
        saved = load_checkpoint(self.checkpoint)
        self.assertEqual(saved.result_sha256, hashlib.sha256(self.result.read_bytes()).hexdigest())
        stale = self.root / 'previous.json'
        stale.write_bytes(previous)
        # Distinct completed_at values ensure these are separate scan results.
        self.assertNotEqual(previous, self.result.read_bytes())
        with self.assertRaises(ValueError):
            validate_checkpoint_result(saved, stale)

    def test_failed_rerun_keeps_old_artifacts_but_invalidates_binding(self):
        self.assertEqual(self.run_cli(), 0)
        before_result, before_report = self.result.read_bytes(), self.report.read_bytes()
        with patch.object(cli, 'scan_path', side_effect=OSError('synthetic read failure')):
            self.assertNotEqual(self.run_cli('--force'), 0)
        self.assertEqual(self.result.read_bytes(), before_result)
        self.assertEqual(self.report.read_bytes(), before_report)
        self.assert_aborted_without_success()

    def test_source_mutation_during_scan_blocks_all_publication(self):
        scan = cli.scan_path

        def changing_scan(*args, **kwargs):
            result = scan(*args, **kwargs)
            self.code.write_text('int changed;\n', encoding='utf-8')
            return result

        with patch.object(cli, 'scan_path', side_effect=changing_scan):
            self.assertNotEqual(self.run_cli(), 0)
        self.assertFalse(self.result.exists())
        self.assertFalse(self.report.exists())
        self.assert_aborted_without_success()

    def test_source_mutation_during_report_preparation_blocks_publication(self):
        render = cli.build_audit_report

        def changing_report(*args, **kwargs):
            report = render(*args, **kwargs)
            self.code.write_text('int changed_after_scan;\n', encoding='utf-8')
            return report

        with patch.object(cli, 'build_audit_report', side_effect=changing_report):
            self.assertNotEqual(self.run_cli(), 0)
        self.assertFalse(self.result.exists())
        self.assertFalse(self.report.exists())
        self.assert_aborted_without_success()

    def test_report_preparation_failure_does_not_publish_result(self):
        with patch.object(cli, 'build_audit_report', side_effect=ValueError('synthetic render failure')):
            self.assertNotEqual(self.run_cli(), 0)
        self.assertFalse(self.result.exists())
        self.assertFalse(self.report.exists())
        self.assert_aborted_without_success()

    def test_report_write_failure_has_no_success_commit(self):
        replace = cli.os.replace

        def failing_replace(source, destination):
            if Path(destination) == self.report:
                raise OSError('synthetic report publication failure')
            return replace(source, destination)

        with patch.object(cli.os, 'replace', side_effect=failing_replace):
            self.assertNotEqual(self.run_cli(), 0)
        # Multi-file publication is not transactional: a result may exist, but
        # the checkpoint and journal must never certify this attempt as success.
        self.assertFalse(self.report.exists())
        self.assert_aborted_without_success()

    def test_existing_report_is_preserved_without_force(self):
        self.report.write_bytes(b'previous-report')
        self.assertNotEqual(self.run_cli(), 0)
        self.assertEqual(self.report.read_bytes(), b'previous-report')
        self.assertFalse(self.result.exists())
        self.assertFalse(self.checkpoint.exists())
        self.assertFalse(self.journal.exists())

    def test_conflicting_engine_options_have_no_side_effects(self):
        self.assertNotEqual(self.run_cli('--engine-files-from', 'files.txt',
                                         '--engine-profile', 'profile.json'), 0)
        self.assertFalse(self.result.exists())
        self.assertFalse(self.checkpoint.exists())
        self.assertFalse(self.journal.exists())


if __name__ == '__main__':
    unittest.main()
