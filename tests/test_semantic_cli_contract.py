"""Public CLI with local synthetic sources, no LLM/analyzer/network."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ohvul import cli
from ohvul.report.schema import validate_report_against_result
from ohvul.verify import validate_result


class SemanticCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base/'source'
        self.source.mkdir()
        (self.source/'a.c').write_text('int f(void){return 0;}\n', encoding='utf-8')
        self.manifest = self.base/'files.txt'
        self.manifest.write_text('a.c\n', encoding='utf-8')
        self.output = self.base/'result.json'
        self.report = self.base/'report.json'
        self.checkpoint = self.base/'checkpoint.json'
        self.journal = self.base/'journal.jsonl'
        self.args = ['ohvul', str(self.source), '--semantic-files-from', str(self.manifest),
                     '--output', str(self.output), '--report-output', str(self.report),
                     '--checkpoint', str(self.checkpoint), '--journal', str(self.journal)]

    def run_cli(self):
        with patch.object(sys, 'argv', self.args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cli.main()

    def assert_blocked(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(self.report.exists())
        checkpoint = json.loads(self.checkpoint.read_bytes())
        self.assertEqual(checkpoint['state'], 'blocked')
        self.assertIsNone(checkpoint['result_sha256'])
        events = [json.loads(line)['event'] for line in self.journal.read_text().splitlines()]
        self.assertEqual(events, ['begin', 'abort'])

    def test_zero_findings_preserve_execution_counts(self):
        self.run_cli()
        value = json.loads(self.output.read_bytes())
        self.assertEqual(value['status'], 'completed')
        self.assertEqual(value['semantic_scan']['files_scanned'], 1)
        self.assertEqual(value['semantic_scan']['candidates'], 0)
        self.assertEqual(value['semantic_scan']['analysis_coverage']['status'], 'lexical_only')
        validate_result(value)
        validate_report_against_result(json.loads(self.report.read_bytes()), value)

    def test_missing_selected_file_cannot_publish_success(self):
        self.manifest.write_text('a.c\nmissing.c\n', encoding='utf-8')
        with self.assertRaises(SystemExit):
            self.run_cli()
        self.assert_blocked()

    def test_empty_and_duplicate_lists_block_instead_of_zero_success(self):
        self.manifest.write_text('# empty\n', encoding='utf-8')
        with self.assertRaises(SystemExit):
            self.run_cli()
        self.assert_blocked()

    def test_file_list_change_after_analysis_blocks_publication(self):
        original = cli.identify_components
        def change(root):
            self.manifest.write_text('other.c\n', encoding='utf-8')
            return original(root)
        with patch.object(cli, 'identify_components', side_effect=change), self.assertRaises(SystemExit):
            self.run_cli()
        self.assert_blocked()

    def test_unknown_syntax_is_visible_in_merged_report_input(self):
        (self.source/'a.c').write_text('void f(char*d,char*s,int n){memcpy(d,s,n);', encoding='utf-8')
        self.run_cli()
        value = json.loads(self.output.read_bytes())
        self.assertEqual(value['semantic_scan']['analysis_coverage']['status'], 'partial_lexical_analysis')
        self.assertTrue(value['semantic_scan']['analysis_issues'])
        self.assertTrue(all(x['status']=='candidate' for x in value['findings']))
        validate_report_against_result(json.loads(self.report.read_bytes()), value)

    def test_no_remote_or_external_analyzer_is_invoked(self):
        with patch('ohvul.llm_adapter._open') as network, patch.object(cli, 'scan_engine_profile') as engine:
            self.run_cli()
            network.assert_not_called()
            engine.assert_not_called()


if __name__ == '__main__':
    unittest.main()
