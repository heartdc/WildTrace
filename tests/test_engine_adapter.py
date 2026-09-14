import unittest
from pathlib import Path
from ohvul.engine_adapter import discover_local_engines, normalize_findings, normalize_sarif, normalize_clang_plist, normalize_clang_tidy_text, engine_result_to_audit_result, merge_engine_result, attach_knowledge_candidates, build_local_command, windows_to_wsl_path


class EngineAdapterTests(unittest.TestCase):
    def test_discovery_has_fixed_engine_set(self):
        self.assertEqual([x.name for x in discover_local_engines()], ["clang", "clang-tidy", "semgrep", "codeql", "joern"])

    def test_normalization_forces_candidate_and_safety(self):
        result = normalize_findings({"findings": [{"rule": "x", "location": {"file": "a.c", "line": 3}}]}, engine="clang", source_root=Path("."), engine_version="test")
        self.assertEqual(result["findings"][0]["status"], "candidate")
        self.assertTrue(result["safety"]["local_only"])

    def test_unknown_engine_rejected(self):
        with self.assertRaises(ValueError):
            normalize_findings({"findings": []}, engine="fake", source_root=Path("."))

    def test_sarif_normalization(self):
        raw = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "R1", "message": {"text": "x"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"}, "region": {"startLine": 4}}}]}]}]}
        result = normalize_sarif(raw, engine="semgrep", source_root=Path("."))
        self.assertEqual(result["findings"][0]["location"]["line"], 4)

    def test_command_is_local_and_allowlisted(self):
        self.assertEqual(build_local_command("semgrep", "semgrep", Path("."))[0], "semgrep")
        with self.assertRaises(ValueError):
            build_local_command("semgrep", "evil", Path("."))

    def test_clang_plist_normalization(self):
        raw = b'''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>diagnostics</key><array><dict><key>check_name</key><string>core.NullDereference</string><key>description</key><string>possible null dereference</string><key>location</key><dict><key>file</key><string>a.c</string><key>line</key><integer>2</integer></dict></dict></array></dict></plist>'''
        result = normalize_clang_plist(raw, source_root=Path('.'), engine_version='22.1.8')
        self.assertEqual(result['findings'][0]['rule'], 'core.NullDereference')
        self.assertEqual(result['findings'][0]['status'], 'candidate')
        self.assertEqual(result['findings'][0]['cwe_candidate'], 'CWE-476')

    def test_windows_path_mapping(self):
        self.assertEqual(windows_to_wsl_path(Path('C:/Projects/OpenHarmony')), '/mnt/c/Projects/OpenHarmony')

    def test_compile_args_contract_is_tuple(self):
        from ohvul.engine_adapter import run_wsl_clang_analyzer
        with self.assertRaises(ValueError):
            run_wsl_clang_analyzer(Path(__file__), Path('.'), compile_args=['-I', '.'])

    def test_clang_tidy_text_normalization(self):
        text = 'a.c:7:4: warning: possible issue [clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling]\n'
        result = normalize_clang_tidy_text(text, source_root=Path('.'), engine_version='22.1.8')
        self.assertEqual(result['engine'], 'clang-tidy')
        self.assertEqual(result['findings'][0]['location']['line'], 7)
        self.assertEqual(result['findings'][0]['rule'], 'clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling')
        self.assertEqual(result['findings'][0]['cwe_candidate'], 'CWE-676')
        self.assertEqual(result['findings'][0]['cwe_mapping_source'], 'builtin_engine_rule_map')
        self.assertEqual(result['findings'][0]['cwe_mapping_version'], '1')

    def test_engine_projection_validates_with_result_checker(self):
        from ohvul.verify import validate_result
        normalized = normalize_findings({'findings': [{'rule': 'R1', 'description': 'candidate', 'location': {'file': 'a.c', 'line': 2}, 'evidence': {'column': 4}}]}, engine='clang', source_root=Path('.'), engine_version='22.1.8')
        result = engine_result_to_audit_result(normalized, source_root=Path('.'))
        self.assertEqual(validate_result(result), 1)

    def test_engine_projection_binds_snapshot(self):
        normalized = normalize_findings({'findings': []}, engine='clang', source_root=Path('.'))
        result = engine_result_to_audit_result(normalized, source_root=Path('.'), source_snapshot_sha256='a'*64)
        self.assertEqual(result['scan']['source_snapshot_sha256'], 'a'*64)

    def test_engine_merge_validates_with_result_checker(self):
        from ohvul.verify import validate_result
        base = {'schema_version': '0.3', 'scan': {'root': str(Path('.').resolve())}, 'findings': [], 'evidence_bundles': [], 'safety': {}}
        normalized = normalize_findings({'findings': [{'rule': 'R1', 'description': 'candidate', 'location': {'file': 'a.c', 'line': 2}}]}, engine='clang', source_root=Path('.'))
        engine = engine_result_to_audit_result(normalized, source_root=Path('.'))
        merged = merge_engine_result(base, engine, source_root=Path('.'))
        self.assertEqual(validate_result(merged), 1)

    def test_engine_merge_rejects_snapshot_mismatch(self):
        base = {'schema_version': '0.3', 'scan': {'root': str(Path('.').resolve()), 'source_snapshot_sha256': 'a'*64}, 'findings': [], 'evidence_bundles': [], 'safety': {}}
        engine = {'schema_version': '0.3', 'scan': {'root': str(Path('.').resolve()), 'source_snapshot_sha256': 'b'*64}, 'findings': [], 'evidence_bundles': []}
        with self.assertRaises(ValueError):
            merge_engine_result(base, engine, source_root=Path('.'))

    def test_engine_merge_rejects_unvalidated_result(self):
        base = {'schema_version': '0.3', 'scan': {'root': str(Path('.').resolve())}, 'findings': [], 'evidence_bundles': [], 'safety': {}}
        engine = {'schema_version': '0.3', 'scan': {'root': str(Path('.').resolve())}, 'findings': [{'alert_id': 'x'}], 'evidence_bundles': []}
        with self.assertRaises((ValueError, KeyError)):
            merge_engine_result(base, engine, source_root=Path('.'))

    def test_knowledge_candidate_is_cwe_filtered(self):
        db = {'records': [{'id': 'CVE-2024-1234', 'cwe': ['CWE-476'], 'summary': 'x', 'component': 'camera', 'affected_versions': ['1'], 'fixed_versions': ['2'], 'source': 'local'}], 'records_sha256': 'x'}
        normalized = normalize_findings({'findings': [{'rule': 'core.NullDereference', 'location': {'file': 'a.c', 'line': 2}}]}, engine='clang', source_root=Path('.'))
        result = engine_result_to_audit_result(normalized, source_root=Path('.'))
        attach_knowledge_candidates(result, db, component='camera', version='1')
        self.assertEqual(result['known_vulnerability_matches'][0]['matches'][0]['id'], 'CVE-2024-1234')
        from ohvul.verify import validate_result
        self.assertEqual(validate_result(result), 2)


if __name__ == "__main__":
    unittest.main()
