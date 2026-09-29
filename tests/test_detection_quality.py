"""Regression tests for detection-quality fixes (audit priority 3, 2026-09-29).

Covers: P9 format-argument position, P4 scoring variable, P6 caller-side
check no longer silently dropping findings, comment-safe function
splitting, and cross_uaf dedup / facts collision / param alignment.
"""
import tempfile, unittest
from pathlib import Path

from ohvul.autopilot import _iter_functions, scan_p9, scan_p6, CallGraph
from ohvul.cross_uaf import build_facts, scan_cross_uaf, _parse_params


def _write(root: Path, name: str, code: str) -> Path:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return p


class P9FormatArgumentTests(unittest.TestCase):
    def scan(self, code):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c", code)
            return scan_p9(root)

    def test_literal_formats_are_not_flagged(self):
        findings = self.scan(
            'void log_msg(const char *user) {\n'
            '    fprintf(stderr, "fixed %s", user);\n'
            '    char buf[32];\n'
            '    snprintf(buf, sizeof(buf), "ok %s", user);\n'
            '}\n')
        self.assertEqual(findings, [])

    def test_variable_format_is_flagged_at_correct_argument(self):
        findings = self.scan(
            'void log_msg(const char *user) {\n'
            '    fprintf(stderr, user);\n'
            '    printf(user);\n'
            '}\n')
        vars_flagged = {f.struct_type for f in findings}
        self.assertIn("user", vars_flagged)
        self.assertNotIn("stderr", vars_flagged)
        self.assertNotIn("buf", vars_flagged)

    def test_syslog_flags_format_not_priority(self):
        findings = self.scan(
            '#include <syslog.h>\n'
            'void log_msg(const char *user) {\n'
            '    syslog(LOG_ERR, user);\n'
            '}\n')
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual(f.struct_type, "user")

    def test_nested_call_args_do_not_confuse_extraction(self):
        # format slot holds a literal → no finding even with a call in args
        findings = self.scan(
            'void log_msg(const char *user) {\n'
            '    printf("%s", trim(user));\n'
            '}\n')
        self.assertEqual(findings, [])


class P4ScoringTests(unittest.TestCase):
    def test_scoring_uses_size_variable_not_function_name(self):
        from ohvul.autopilot import scan_p4
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   'void copy(char *dst, const char *src, int len) {\n'
                   '    memcpy(dst, src, len);\n'
                   '}\n')
            findings = scan_p4(root)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.struct_type, "len")  # was "memcpy" (audit P1)
        self.assertIn("+20 (size is direct parameter)", f.confidence_factors)


class P6CallerCheckTests(unittest.TestCase):
    CODE = (
        'void consume(int *data) {\n'
        '    data[0] = data[1] + data[2];\n'
        '}\n'
        'void guarded(int *data) {\n'
        '    if (!data) return;\n'
        '    consume(data);\n'
        '}\n'
        'void unguarded(int *info) {\n'
        '    consume(info);\n'
        '}\n'
    )

    def test_caller_null_check_lowers_confidence_but_keeps_finding(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c", self.CODE)
            cg = CallGraph()
            cg.build(root)
            findings = scan_p6(root, call_graph=cg)
        # Old behavior: the finding for consume(data) was silently dropped
        # just because a caller happened to have a parameter named "data".
        consume_findings = [x for x in findings if x.function == "consume"]
        self.assertEqual(len(consume_findings), 1)
        f = consume_findings[0]
        self.assertIn("-20 (caller null-checks arg)", f.confidence_factors)
        # sanity: the same code without the guarded caller keeps the
        # finding at the plain score (no caller-side factor)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   'void consume(int *data) {\n'
                   '    data[0] = data[1] + data[2];\n'
                   '}\n'
                   'void unguarded(int *info) {\n'
                   '    consume(info);\n'
                   '}\n')
            cg2 = CallGraph()
            cg2.build(root)
            plain = scan_p6(root, call_graph=cg2)
        plain_f = [x for x in plain if x.function == "consume"][0]
        self.assertNotIn("-20 (caller null-checks arg)", plain_f.confidence_factors)
        self.assertGreater(plain_f.confidence, f.confidence)


class FunctionSplittingTests(unittest.TestCase):
    def test_apostrophe_in_comment_does_not_drop_function(self):
        text = ('/* don\'t do this at home */\n'
                'int f(int *p) {\n'
                '    return p[0];\n'
                '}\n')
        names = [n for n, *_ in _iter_functions(text)]
        self.assertIn("f", names)

    def test_brace_in_comment_does_not_truncate_body(self):
        text = ('int g(char *dst, const char *src, int len) {\n'
                '    /* } this brace is a comment */\n'
                '    memcpy(dst, src, len);\n'
                '}\n')
        funcs = {n: cl for n, p, l, b, cl in _iter_functions(text)}
        self.assertIn("memcpy(dst, src, len)", funcs["g"])

    def test_line_comment_brace_does_not_swallow_next_function(self):
        text = ('void a(void) {\n'
                '    // { oops\n'
                '}\n'
                'void b(void) {\n'
                '}\n')
        names = [n for n, *_ in _iter_functions(text)]
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_else_if_is_not_a_function(self):
        text = ('void h(int *p) {\n'
                '    if (p) {\n'
                '    } else if (p[0]) {\n'
                '        p[1] = 0;\n'
                '    }\n'
                '}\n')
        names = [n for n, *_ in _iter_functions(text)]
        self.assertNotIn("if", names)
        self.assertIn("h", names)

    def test_define_macro_is_not_a_function(self):
        text = '#define SAFE_FREE(p) { free(p); }\n'
        names = [n for n, *_ in _iter_functions(text)]
        self.assertNotIn("SAFE_FREE", names)

    def test_block_comment_lines_preserved_for_offsets(self):
        # 3 lines of block comment inside the body must not shift the
        # newline count used for line offsets downstream
        text = ('void k(int *p) {\n'
                '    /* line one\n'
                '       line two\n'
                '       line three */\n'
                '    p[0] = 1;\n'
                '}\n')
        for name, params, line, body, cleaned in _iter_functions(text):
            self.assertEqual(name, "k")
            self.assertEqual(cleaned.count('\n'), body.count('\n'))


class CrossUafDedupTests(unittest.TestCase):
    def test_pattern_b_emits_once_per_callee_var(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   'void sink(char *p) { free(p); }\n'
                   'void f(char *a, char *b) {\n'
                   '    sink(a); sink(a); sink(a);\n'
                   '    a[0] = 1;\n'
                   '    sink(b);\n'
                   '    b[0] = 1;\n'
                   '}\n')
            findings = scan_cross_uaf(root, build_facts(root))
        b_findings = [f for f in findings
                      if f.finding_id.startswith("P8B_") and f.function == "f"]
        a_count = [f for f in b_findings if f.struct_type == "a"]
        self.assertEqual(len(a_count), 1)  # was 3 (one per call site)

    def test_null_reset_after_freeing_call_suppresses_pattern_b(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   'void sink(char *p) { free(p); }\n'
                   'void f(char *a) {\n'
                   '    sink(a);\n'
                   '    a = NULL;\n'
                   '    a[0] = 1;\n'
                   '}\n')
            findings = scan_cross_uaf(root, build_facts(root))
        self.assertFalse([f for f in findings if f.finding_id.startswith("P8B_")])

    def test_same_name_statics_are_dropped_not_misattributed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "a.c",
                   'static void OnEvt(char *e) { free(e); }\n')
            _write(root, "b.c",
                   'static void OnEvt(char *e) { e[0] = 1; }\n')
            _write(root, "main.c",
                   'void caller(char *x) {\n'
                   '    OnEvt(x);\n'
                   '    x[0] = 1;\n'
                   '}\n')
            facts = build_facts(root)
        self.assertNotIn("OnEvt", facts)  # ambiguous → conservative drop

    def test_param_positions_align_across_fn_pointer_params(self):
        names = _parse_params("int (*cb)(int), char *p")
        self.assertEqual(names, ["", "p"])  # cb slot kept, p at index 1

    def test_pattern_a_survives_earlier_legitimate_call(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.c",
                   'void use(char *p) { p[0] = 1; }\n'
                   'void f(char *ptr) {\n'
                   '    use(ptr);\n'          # legitimate, before the free
                   '    free(ptr);\n'
                   '    use(ptr);\n'          # the actual UAF
                   '}\n')
            findings = scan_cross_uaf(root, build_facts(root))
        self.assertTrue([f for f in findings if f.finding_id.startswith("P8A_")])


if __name__ == "__main__":
    unittest.main()
