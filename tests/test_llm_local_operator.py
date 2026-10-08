"""Exercise the operator command in temporary sources; never use real keys."""
import getpass
import io
import json
from pathlib import Path
import tempfile
import unittest
import warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from tests.test_llm_expanded import ExpandedFixture
from tools import llm_local as operator
from ohvul import llm_review as review
from ohvul.llm_adapter import LlmTransportError


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fx = ExpandedFixture(self.tmp.name)
        self.config = self.fx.base / 'operator.json'
        self.output = self.fx.base / 'operator-run'
        self.data = dict(schema='llm-local-operator-0.1',
                         summary=str(self.fx.inputs[0]), queue=str(self.fx.inputs[1]),
                         context=str(self.fx.inputs[2]), source_roots={k: str(v) for k, v in self.fx.roots.items()},
                         evidence=str(self.fx.evidence_path), groups=self.fx.ids,
                         base_url=review.GLM_BASE_URL, model=review.GLM_MODEL, timeout=300,
                         max_tokens=3072, max_calls=1)
        self.config.write_text(json.dumps(self.data), encoding='utf-8')
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.enterContext(redirect_stdout(self.stdout))
        self.enterContext(redirect_stderr(self.stderr))
        self.model = self.enterContext(patch.object(review, 'chat_completion', side_effect=self.fx.reply))
        self.key = self.enterContext(patch.object(operator, '_prompt_key', return_value='dummy-local-credential'))

    def invoke(self, mode, *args):
        return operator.main([mode, '--config', str(self.config), '--output', str(self.output), *args])

    def test_plan_never_requests_secret_or_network(self):
        self.assertEqual(self.invoke('plan'), 0)
        self.key.assert_not_called()
        self.model.assert_not_called()
        plan = json.loads((self.output / 'plan.json').read_bytes())
        self.assertEqual(plan['timeout'], 300)
        self.assertEqual(plan['maximum_requested_output_tokens'], 3072)

    def test_run_requires_explicit_network_permission(self):
        self.assertEqual(self.invoke('run'), 1)
        self.key.assert_not_called()
        self.model.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_run_and_both_offline_checks(self):
        self.assertEqual(self.invoke('run', '--allow-network'), 0)
        self.assertEqual(self.invoke('verify'), 0)
        self.assertEqual(self.invoke('inspect'), 0)
        self.assertEqual(self.key.call_count, 1)
        self.assertEqual(self.model.call_count, 1)
        for path in self.output.glob('*.json'):
            self.assertNotIn(b'dummy-local-credential', path.read_bytes())
        self.assertNotIn('dummy-local-credential', self.stdout.getvalue() + self.stderr.getvalue())

    def test_failed_provider_stays_incomplete(self):
        self.model.side_effect = LlmTransportError('http_status_403')
        self.assertEqual(self.invoke('run', '--allow-network'), 1)
        self.assertEqual(self.invoke('inspect'), 0)
        self.assertEqual(self.invoke('verify'), 1)
        self.assertEqual(self.model.call_count, 1)
        self.assertIn('bound_incomplete', self.stdout.getvalue())

    def test_no_overwrite_and_unknown_group_before_key_prompt(self):
        self.output.mkdir()
        self.assertEqual(self.invoke('run', '--allow-network'), 1)
        self.key.assert_not_called()
        self.output = self.fx.base / 'different'
        self.assertEqual(self.invoke('run', '--allow-network', '--group', 'not-present'), 1)
        self.key.assert_not_called()

    def test_config_key_or_unknown_fields_are_rejected(self):
        self.data['api_key'] = 'dummy-never-accepted'
        self.config.write_text(json.dumps(self.data), encoding='utf-8')
        self.assertEqual(self.invoke('run', '--allow-network'), 1)
        self.key.assert_not_called()
        self.model.assert_not_called()

    def test_offline_mode_cannot_opt_into_credentials(self):
        self.assertEqual(self.invoke('plan', '--allow-network'), 1)
        self.assertEqual(self.invoke('inspect', '--key-source', 'environment'), 1)
        self.key.assert_not_called()

    def test_explicit_environment_source_does_not_prompt(self):
        with patch.dict('os.environ', {'OSLOVELACE_API_KEY': 'dummy-environment-key'}):
            self.assertEqual(self.invoke('run', '--allow-network', '--key-source', 'environment'), 0)
        self.key.assert_not_called()
        self.assertEqual(self.model.call_args.kwargs['api_key'], 'dummy-environment-key')


class HiddenPromptTests(unittest.TestCase):
    def test_no_plaintext_fallback_without_tty(self):
        with patch.object(operator.sys.stdin, 'isatty', return_value=False), patch.object(getpass, 'getpass') as prompt:
            with self.assertRaises(ValueError): operator._prompt_key()
            prompt.assert_not_called()

    def test_echo_warning_is_error(self):
        def cannot_hide(*args):
            warnings.warn('cannot hide input', getpass.GetPassWarning)
            return 'must-not-be-returned'
        with patch.object(operator.sys.stdin, 'isatty', return_value=True), patch.object(getpass, 'getpass', side_effect=cannot_hide):
            with self.assertRaises(getpass.GetPassWarning): operator._prompt_key()


if __name__ == '__main__': unittest.main()
