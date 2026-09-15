"""Synthetic local evidence with mocked model transport only."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tests.test_review_queue import BatchFixture
from tests.test_llm_review import completion, valid_draft
from ohvul import llm_review as review, review_queue, review_context, review_evidence, review_handoff
from ohvul import llm_evidence
from ohvul.llm_adapter import LlmTransportError


class ExpandedFixture:
    def __init__(self, base):
        self.base = Path(base).resolve()
        self.f = BatchFixture(self.base)
        self.roots = {'one': self.f.source}
        self.context_path = self.base / 'context.json'
        self.evidence_path = self.base / 'evidence.json'
        review_queue.write_review_queue(self.f.summary_path, self.f.output)
        review_context.write_review_context(self.f.output, self.f.summary_path, self.roots, self.context_path)
        self.expansion = review_evidence.write_review_evidence(
            self.f.summary_path, self.f.output, self.context_path, self.roots, self.evidence_path)
        self.queue = json.loads(self.f.output.read_bytes())
        self.context = json.loads(self.context_path.read_bytes())
        self.ids = [self.queue['groups'][0]['group_id']]
        self.inputs = [self.f.summary_path, self.f.output, self.context_path, self.roots]

    def reply(self, messages, **settings):
        request = json.loads(messages[1]['content'])
        draft = valid_draft(request)
        ref = next((x['ref'] for x in request['evidence_catalog'] if x['kind'] == 'source_fragment'), 'L2')
        draft['assessments'][2].update(status='local_observation', evidence_refs=[ref])
        return completion(request, draft, max_tokens=settings['max_tokens'],
                          request_sha256=review.request_digest(request, settings['model'], settings['max_tokens']))


class ExpandedReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fx = ExpandedFixture(self.tmp.name)
        self.output = self.fx.base / 'run'
        self.model = self.enterContext(patch.object(review, 'chat_completion', side_effect=self.fx.reply))
        self.enterContext(redirect_stdout(io.StringIO()))

    def run_review(self, **settings):
        options = dict(allow_network=True, api_key='dummy-ephemeral-credential', evidence_path=self.fx.evidence_path)
        options.update(settings)
        return review.run_review(*self.fx.inputs, self.output, self.fx.ids, **options)

    def test_expansion_is_in_request_and_verified_offline(self):
        value = self.run_review(timeout=300)
        self.assertEqual(value['status'], 'completed')
        prompt = self.model.call_args.args[0]
        request = json.loads(prompt[1]['content'])
        self.assertIn('NOT AST/CFG', prompt[0]['content'])
        entry = next(x for x in request['evidence_catalog'] if x['ref'] == 'E1')
        self.assertEqual(entry['file'], 'a.c')
        self.assertEqual(entry['lines'][1]['text'], '    return *p;')
        self.assertNotIn(str(self.fx.f.source), prompt[1]['content'])
        verified = review.verify_review(self.output, *self.fx.inputs, evidence_path=self.fx.evidence_path)
        self.assertEqual(verified, value)
        self.assertEqual(self.model.call_count, 1)

    def test_old_request_and_prompt_stay_byte_compatible(self):
        request = review.make_request(self.fx.queue['groups'][0], self.fx.context['contexts'][0])
        self.assertEqual(review.messages_for(request)[0]['content'], review.SYSTEM_PROMPT)
        self.assertNotIn('evidence_selection', request)
        self.run_review(evidence_path=None)
        review.verify_review(self.output, *self.fx.inputs)

    def test_plan_needs_no_credential_and_records_exact_expansion_hash(self):
        self.run_review(plan_only=True, allow_network=False, api_key=None)
        self.model.assert_not_called()
        plan = json.loads((self.output / 'plan.json').read_bytes())
        self.assertEqual(plan['bindings']['evidence_sha256'], review.sha256(self.fx.evidence_path.read_bytes()))
        self.assertEqual(plan['prompt_version'], llm_evidence.EXPANDED_PROMPT_VERSION)

    def test_changed_expansion_rejected_before_model(self):
        value = copy.deepcopy(self.fx.expansion)
        value['evidence'][0]['lines'][0]['text'] = 'fabricated'
        self.fx.evidence_path.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaises(ValueError): self.run_review()
        self.model.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_inspector_does_not_guess_missing_expansion_path(self):
        self.run_review()
        with self.assertRaises(ValueError): review.inspect_review(self.output, *self.fx.inputs)

    def test_expansion_mutation_during_call_never_publishes_success(self):
        def change(messages, **settings):
            result = self.fx.reply(messages, **settings)
            self.fx.evidence_path.write_bytes(self.fx.evidence_path.read_bytes() + b' ')
            return result
        self.model.side_effect = change
        self.assertEqual(self.run_review()['status'], 'incomplete')

    def test_missing_selected_group_is_rejected_without_payment(self):
        self.fx.ids = ['RG-not-present']
        with self.assertRaises(ValueError): self.run_review()
        self.model.assert_not_called()

    def test_budget_omissions_are_explicit_and_unreferencable(self):
        request = review.make_request(self.fx.queue['groups'][0], self.fx.context['contexts'][0])
        value = copy.deepcopy(self.fx.expansion)
        for item in value['evidence']:
            item['lines'][0]['text'] = 'x' * 70000
        # Projection-only test: the runtime separately validates original source.
        projected = llm_evidence.extend_request(request, value)
        self.assertEqual(projected['evidence_selection']['included_evidence_ids'], [])
        self.assertTrue(projected['evidence_selection']['omitted_evidence_ids'])
        self.assertLessEqual(len(review.canonical_bytes(projected)), 48 * 1024)
        draft = valid_draft(projected)
        draft['assessments'][2].update(status='local_observation', evidence_refs=['E1'])
        with self.assertRaises(ValueError): review.validate_draft(draft, projected)

    def test_truncation_and_incomplete_search_are_not_hidden(self):
        request = review.make_request(self.fx.queue['groups'][0], self.fx.context['contexts'][0])
        value = copy.deepcopy(self.fx.expansion)
        value['evidence'][0]['truncated'] = True
        value['groups'][0]['definition_traversal_complete'] = False
        projected = llm_evidence.extend_request(request, value)
        self.assertTrue(projected['evidence_selection']['truncated_evidence_ids'])
        self.assertFalse(projected['evidence_selection']['definition_traversal_complete'])

    def test_foreign_source_fragment_rejected(self):
        request = review.make_request(self.fx.queue['groups'][0], self.fx.context['contexts'][0])
        value = copy.deepcopy(self.fx.expansion)
        value['evidence'][0]['file_sha256'] = '0' * 64
        with self.assertRaises(ValueError): llm_evidence.extend_request(request, value)

    def test_expanded_suggestions_survive_handoff_without_closing_tasks(self):
        self.run_review()
        value = review_handoff.build_review_handoff(*self.fx.inputs, [self.output],
                                                    evidence_path=self.fx.evidence_path)
        catalog = value['groups'][0]['evidence_catalog']
        self.assertTrue(any(x['ref'] == 'E1' for x in catalog))
        task = value['groups'][0]['tasks'][2]
        self.assertEqual(task['model_assessments'][0]['evidence_refs'], ['E1'])
        self.assertEqual(task['answer'], 'unknown')
        review_handoff.validate_review_handoff(value, *self.fx.inputs, [self.output],
                                               evidence_path=self.fx.evidence_path)

    def test_timeout_keeps_failure_unknown_and_never_retries(self):
        self.model.side_effect = LlmTransportError('transport_timeout')
        value = self.run_review(timeout=300)
        self.assertEqual(value['failed_calls'], 1)
        self.assertFalse(value['usage']['complete'])
        inspected = review.inspect_review(self.output, *self.fx.inputs, evidence_path=self.fx.evidence_path)
        self.assertEqual(inspected['status'], 'bound_incomplete')
        self.assertEqual(self.model.call_count, 1)


if __name__ == '__main__': unittest.main()
