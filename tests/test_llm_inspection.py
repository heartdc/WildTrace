"""Offline inspection of successful AND failed model runs, with no HTTP calls."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from ohvul import llm_review as review
from ohvul import review_context, review_queue
from ohvul.llm_adapter import LlmTransportError
from tests.test_review_queue import BatchFixture, raw_finding
from tests.test_llm_review import completion


class ReviewRunFixture:
    def __init__(self, base):
        self.base = base
        self.f = BatchFixture(base, findings=[
            raw_finding(description='unused local value'),
            raw_finding(rule='core.NullDereference', description='possible null access'),
            raw_finding(rule='unix.Malloc', description='allocation needs review')])
        self.roots = {'one': self.f.source}
        review_queue.write_review_queue(self.f.summary_path, self.f.output)
        self.context_path = base / 'context.json'
        review_context.write_review_context(self.f.output, self.f.summary_path,
                                           self.roots, self.context_path)
        self.queue = json.loads(self.f.output.read_bytes())
        self.ids = [g['group_id'] for g in self.queue['groups']]

    def reply(self, messages, **kwargs):
        return completion(json.loads(messages[1]['content']))

    def run(self, output, ids=None, reply=None):
        with patch.object(review, 'chat_completion', side_effect=reply or self.reply), redirect_stdout(io.StringIO()):
            return review.run_review(self.f.summary_path, self.f.output, self.context_path,
                                     self.roots, output, self.ids if ids is None else ids,
                                     allow_network=True, api_key='test-ephemeral-only', max_calls=3)

    def inspect(self, output):
        return review.inspect_review(output, self.f.summary_path, self.f.output,
                                     self.context_path, self.roots)


class LlmInspectionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.fx = ReviewRunFixture(Path(tmp.name).resolve())
        self.output = self.fx.base / 'run'

    def failure(self, *args, **kwargs):
        raise LlmTransportError('http_status_403')

    def rewrite(self, records=None, plan=None):
        if plan is None:
            plan = json.loads((self.output / 'plan.json').read_bytes())
        if records is None:
            records = [json.loads(p.read_bytes()) for p in sorted(self.output.glob('item-*.json'))]
        (self.output / 'plan.json').write_text(json.dumps(plan), encoding='utf-8')
        for i, record in enumerate(records, 1):
            (self.output / f'item-{i:04d}.json').write_text(json.dumps(record), encoding='utf-8')
        (self.output / 'summary.json').write_text(
            json.dumps(review._summary(plan, records, bindings_valid=True)), encoding='utf-8')
        return records, plan

    def test_failed_run_is_inspectable_but_not_successfully_verified(self):
        original = self.fx.run(self.output, reply=self.failure)
        report = self.fx.inspect(self.output)
        self.assertEqual(report['summary'], original)
        self.assertEqual(report['status'], 'bound_incomplete')
        self.assertEqual([r['outcome'] for r in report['records']],
                         ['transport_failed', 'not_run', 'not_run'])
        self.assertEqual(original['calls_attempted'], 1)
        self.assertFalse(original['usage']['complete'])
        with self.assertRaises(ValueError):
            review.verify_review(self.output, self.fx.f.summary_path, self.fx.f.output,
                                 self.fx.context_path, self.fx.roots)

    def test_completed_run_is_inspectable_without_new_model_calls(self):
        self.fx.run(self.output, ids=self.fx.ids[:1])
        with patch.object(review, 'chat_completion', side_effect=AssertionError('network')):
            result = self.fx.inspect(self.output)
        self.assertEqual(result['status'], 'bound_completed')
        self.assertEqual(result['summary']['valid_drafts'], 1)
        self.assertEqual(len(result['artifact_bindings']), 3)

    def test_prepared_only_run_is_not_a_finished_execution(self):
        with redirect_stdout(io.StringIO()):
            review.run_review(self.fx.f.summary_path, self.fx.f.output, self.fx.context_path,
                              self.fx.roots, self.output, self.fx.ids[:1], plan_only=True)
        with self.assertRaises((OSError, ValueError)):
            self.fx.inspect(self.output)

    def test_new_policy_rejects_calls_after_transport_failure(self):
        self.fx.run(self.output, reply=self.failure)
        records, plan = self.rewrite()
        records[1] = {**records[0], 'group_id': records[1]['group_id'],
                      'request_sha256': records[1]['request_sha256']}
        self.rewrite(records, plan)
        with self.assertRaisesRegex(ValueError, 'transport|policy'):
            self.fx.inspect(self.output)

    def test_historical_unversioned_failure_run_is_not_rewritten(self):
        self.fx.run(self.output, reply=self.failure)
        records, plan = self.rewrite()
        plan.pop('execution_policy', None)
        for record in records[1:]:
            record.update(outcome='transport_failed', error_code='http_status_403', seconds=1.0)
        self.rewrite(records, plan)
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        result = self.fx.inspect(self.output)
        self.assertEqual(result['execution_policy'], 'legacy_unspecified')
        self.assertEqual(result['summary']['calls_attempted'], 3)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_unknown_execution_policy_is_rejected(self):
        self.fx.run(self.output, reply=self.failure)
        records, plan = self.rewrite()
        plan['execution_policy'] = 'retry_forever'
        self.rewrite(records, plan)
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_arbitrary_error_text_is_not_a_transport_receipt(self):
        self.fx.run(self.output, reply=self.failure)
        records, plan = self.rewrite()
        records[0]['error_code'] = 'arbitrary upstream message'
        self.rewrite(records, plan)
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_missing_record_is_rejected(self):
        self.fx.run(self.output, reply=self.failure)
        (self.output / 'item-0002.json').unlink()
        with self.assertRaises((OSError, ValueError)):
            self.fx.inspect(self.output)

    def test_not_run_must_have_prior_failure_and_zero_time(self):
        self.fx.run(self.output, reply=self.failure)
        records, plan = self.rewrite()
        records[0].update(outcome='not_run', error_code='prior_transport_failure', seconds=0)
        self.rewrite(records, plan)
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_summary_cannot_relabel_failure_as_success(self):
        self.fx.run(self.output, reply=self.failure)
        path = self.output / 'summary.json'
        value = json.loads(path.read_bytes())
        value['status'] = 'completed'
        path.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_rejected_output_cannot_smuggle_invalid_usage(self):
        self.fx.run(self.output, ids=self.fx.ids[:1], reply=lambda msgs, **kw:
                    completion(json.loads(msgs[1]['content']), finish_reason='length'))
        records, plan = self.rewrite()
        records[0]['completion']['usage'] = {'prompt_tokens': -10, 'completion_tokens': 0, 'total_tokens': -10}
        self.rewrite(records, plan)
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_rejected_output_must_retain_exact_request_binding(self):
        self.fx.run(self.output, ids=self.fx.ids[:1], reply=lambda msgs, **kw:
                    completion(json.loads(msgs[1]['content']), finish_reason='length'))
        records, plan = self.rewrite()
        records[0]['completion']['request_sha256'] = 'f' * 64
        self.rewrite(records, plan)
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_truncated_output_content_digest_still_matters(self):
        self.fx.run(self.output, ids=self.fx.ids[:1], reply=lambda msgs, **kw:
                    completion(json.loads(msgs[1]['content']), finish_reason='length'))
        records, plan = self.rewrite()
        records[0]['completion']['content'] = 'different untrusted content'
        self.rewrite(records, plan)
        with self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_inspection_rechecks_saved_record_bytes(self):
        self.fx.run(self.output, ids=self.fx.ids[:1])
        target = self.output / 'item-0001.json'
        original = review.read_bounded
        altered = False
        def read(path, limit):
            nonlocal altered
            raw = original(path, limit)
            if Path(path) == target and not altered:
                altered = True
                target.write_bytes(raw + b' ')
            return raw
        with patch.object(review, 'read_bounded', side_effect=read), self.assertRaises(ValueError):
            self.fx.inspect(self.output)

    def test_cli_inspect_failure_is_explicit_and_offline(self):
        self.fx.run(self.output, reply=self.failure)
        argv = ['--summary', str(self.fx.f.summary_path), '--queue', str(self.fx.f.output),
                '--context', str(self.fx.context_path), '--source-root', 'one=' + str(self.fx.f.source),
                '--output', str(self.output), '--inspect']
        text = io.StringIO()
        with redirect_stdout(text), patch.object(review, 'chat_completion', side_effect=AssertionError('network')):
            self.assertEqual(review.main(argv), 0)
        self.assertIn('bound_incomplete', text.getvalue())
        self.assertIn('inference_completed=False', text.getvalue())


if __name__ == '__main__':
    unittest.main()
