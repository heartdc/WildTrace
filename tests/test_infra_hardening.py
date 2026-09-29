"""Regression tests for the D-group infrastructure fixes (survey 2026-09-29).

D13: Joern CPG binaries must not be written into the audited tree.
D14: llm_poc reads are byte-bounded (crafted huge files cannot spike memory).
D15: the LIST_FOR_EACH_ENTRY_SAFE macro false positive stays fixed (the
     #define-skip from the detection-quality PR closed it; pinned here).
"""
import tempfile, unittest
from pathlib import Path
from unittest import mock

import ohvul.joern_bridge as joern_bridge
from ohvul.joern_bridge import JoernAnalyzer
from ohvul.llm_poc import _extract_context, _extract_includes, MAX_FILE_READ_BYTES
from ohvul.cross_uaf import build_facts, scan_cross_uaf


class _FakeCompleted:
    returncode = 0
    stdout = "Successfully wrote /tmp/wildtrace-cpg/abc.bin"
    stderr = ""


class CpgLocationTests(unittest.TestCase):
    def test_cpg_is_written_outside_the_audited_tree(self):
        analyzer = JoernAnalyzer("/mnt/d/audit/target")
        captured = {}
        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _FakeCompleted()
        with mock.patch.object(joern_bridge.subprocess, "run",
                               side_effect=fake_run):
            self.assertTrue(analyzer.build_cpg())
        cmd = " ".join(captured["cmd"])
        self.assertNotIn("/mnt/d/audit/target/cpg.bin", cmd)
        self.assertIn("/tmp/wildtrace-cpg", cmd)
        self.assertIn("mkdir -p", cmd)
        self.assertTrue(analyzer.cpg_path.startswith("/tmp/wildtrace-cpg/"))

    def test_cpg_dir_is_configurable(self):
        analyzer = JoernAnalyzer("/mnt/d/audit/target", cpg_dir="/mnt/d/scratch")
        captured = {}
        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _FakeCompleted()
        with mock.patch.object(joern_bridge.subprocess, "run",
                               side_effect=fake_run):
            self.assertTrue(analyzer.build_cpg())
        self.assertTrue(analyzer.cpg_path.startswith("/mnt/d/scratch/"))

    def test_cpg_name_is_stable_per_source_root(self):
        a = JoernAnalyzer("/mnt/d/audit/target")
        b = JoernAnalyzer("/mnt/d/audit/target")
        c = JoernAnalyzer("/mnt/d/other")
        with mock.patch.object(joern_bridge.subprocess, "run",
                               return_value=_FakeCompleted()):
            a.build_cpg(); b.build_cpg(); c.build_cpg()
        self.assertEqual(a.cpg_path, b.cpg_path)   # reused across runs
        self.assertNotEqual(a.cpg_path, c.cpg_path)


class BoundedReadTests(unittest.TestCase):
    def test_context_from_normal_file_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "t.c").write_text("line1\nline2\nline3\n", encoding="utf-8")
            ctx = _extract_context(root, "t.c", 2, context_lines=1)
        self.assertIn("line2", ctx)

    def test_huge_file_is_read_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "big.c").write_bytes(b"// padding\n" * (MAX_FILE_READ_BYTES // 10 + 10))
            ctx = _extract_context(root, "big.c", 1)
        self.assertIn("truncated at", ctx)
        self.assertLessEqual(len(ctx), 3500)  # bounded, not the whole file

    def test_line_beyond_read_head_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "big.c").write_bytes(b"// x\n" * 10)
            # claim a line far beyond the file: explicit, no crash
            ctx = _extract_context(root, "big.c", 10_000_000)
        self.assertIn("beyond", ctx)

    def test_includes_from_huge_file_are_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            head = "#include <stdio.h>\n"
            (root / "big.c").write_text(head, encoding="utf-8")
            (root / "big.c").write_bytes(
                head.encode() + b"// pad\n" * (MAX_FILE_READ_BYTES // 6))
            incs = _extract_includes(root, "big.c")
        self.assertIn("stdio.h", incs)
        self.assertLessEqual(len(incs), 20)


class MacroFalsePositiveTests(unittest.TestCase):
    MACRO_TREE = (
        '#define LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, member) \\\n'
        '    for (pos = (head)->first, n = pos->member; pos; pos = n, n = pos->member)\n'
        'typedef struct Node { struct Node *member; } ListNode;\n'
        'void f(ListNode *pos, ListNode *head) {\n'
        '    ListNode *n;\n'
        '    free(pos);\n'
        '    LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, member);\n'
        '}\n'
    )

    def test_traversal_macro_is_not_a_function(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "t.c").write_text(self.MACRO_TREE, encoding="utf-8")
            facts = build_facts(root)
        self.assertNotIn("LIST_FOR_EACH_ENTRY_SAFE", facts)

    def test_traversal_macro_shape_yields_no_cross_uaf(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "t.c").write_text(self.MACRO_TREE, encoding="utf-8")
            findings = scan_cross_uaf(root, build_facts(root))
        self.assertEqual(findings, [],
                         "dsoftbus LIST_FOR_EACH_ENTRY_SAFE false positive must stay fixed")


if __name__ == "__main__":
    unittest.main()
