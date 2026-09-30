"""Regression tests for the P0 retro-eval fixes (2026-09-30).

P0-1: smart-pointer parameters (shared_ptr/unique_ptr, incl. const&) are
modeled as nullable pointers — GT4's observer-fix sites become scannable.
P0-2: OH truthiness guard macros (CHECK_AND_RETURN*(var, ...)) suppress
P6 — the SocketUpdateCocConnectionParams false-positive class.
"""
import tempfile, unittest
from pathlib import Path

from ohvul.autopilot import scan_p6


def _write(root: Path, name: str, code: str) -> Path:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding="utf-8")
    return p


class SmartPtrParamTests(unittest.TestCase):
    def test_shared_ptr_param_derefs_are_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.cpp",
                   "struct Obs { int a; void Fire(); };\n"
                   "void RegisterObserver(std::shared_ptr<Obs> observer) {\n"
                   "    observer->Fire();\n"
                   "    observer->Fire();\n"
                   "    observer->Fire();\n"
                   "}\n")
            findings = scan_p6(root)
        self.assertTrue(any(f.struct_type == "observer" for f in findings),
                        "shared_ptr param with 3 derefs and no check must be flagged")

    def test_const_ref_smart_ptr_param_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.cpp",
                   "struct Obs { int a; void Fire(); };\n"
                   "void Use(const std::shared_ptr<Obs>& handler) {\n"
                   "    handler->Fire(); handler->Fire(); handler->Fire();\n"
                   "}\n")
            findings = scan_p6(root)
        self.assertTrue(any(f.struct_type == "handler" for f in findings))

    def test_unique_ptr_param_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.cpp",
                   "struct Obs { void Fire(); };\n"
                   "void Use(std::unique_ptr<Obs> sink) {\n"
                   "    sink->Fire(); sink->Fire(); sink->Fire();\n"
                   "}\n")
            findings = scan_p6(root)
        self.assertTrue(any(f.struct_type == "sink" for f in findings))

    def test_checked_smart_ptr_param_is_suppressed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "t.cpp",
                   "struct Obs { void Fire(); };\n"
                   "void RegisterObserver(std::shared_ptr<Obs> observer) {\n"
                   "    if (!observer) return;\n"
                   "    observer->Fire(); observer->Fire(); observer->Fire();\n"
                   "}\n")
            findings = scan_p6(root)
        self.assertFalse([f for f in findings if f.struct_type == "observer"])


class TruthyMacroGuardTests(unittest.TestCase):
    CODE_GUARDED = (
        "#define CHECK_AND_RETURN_LOG_RET(cond, ret, ...) do { "
        "if (!(cond)) return ret; } while (0)\n"
        "void SocketUpdateCocConnectionParams(const BtSocketCocParam *param) {\n"
        "    CHECK_AND_RETURN_LOG_RET(param, -1, \"param is null\");\n"
        "    int a = param->a; int b = param->b; int c = param->c;\n"
        "}\n"
    )
    CODE_UNGUARDED = (
        "void SocketUpdateCocConnectionParams(const BtSocketCocParam *param) {\n"
        "    int a = param->a; int b = param->b; int c = param->c;\n"
        "}\n"
    )

    def test_truthiness_macro_suppresses(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "guarded.c", self.CODE_GUARDED)
            findings = scan_p6(root)
        self.assertFalse([f for f in findings if f.struct_type == "param"],
                         "CHECK_AND_RETURN*(param, ...) truthiness guard must suppress P6")

    def test_same_code_without_macro_still_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "unguarded.c", self.CODE_UNGUARDED)
            findings = scan_p6(root)
        self.assertTrue(any(f.struct_type == "param" for f in findings))

    def test_macro_on_other_var_does_not_suppress(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "other.c",
                   "#define CHECK_AND_RETURN_RET(cond, ret) do { "
                   "if (!(cond)) return ret; } while (0)\n"
                   "void f(const BtParam *param, int *other) {\n"
                   "    CHECK_AND_RETURN_RET(other, -1);\n"
                   "    int a = param->a; int b = param->b; int c = param->c;\n"
                   "}\n")
            findings = scan_p6(root)
        # param is unguarded despite a macro guarding a different variable;
        # `other` itself has no derefs so only param can appear
        self.assertTrue(any(f.struct_type == "param" for f in findings))

    def test_macro_with_comparison_arg_not_treated_as_bare_guard(self):
        # CHECK_*(x != nullptr, ...) guards when NON-null — not a null guard
        # for x; must NOT suppress (conservative: keep the finding)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "cmp.c",
                   "#define CHECK_INVOKE(cond) do { if (cond) g(); } while (0)\n"
                   "void f(const BtParam *param) {\n"
                   "    CHECK_INVOKE(param != nullptr);\n"
                   "    int a = param->a; int b = param->b; int c = param->c;\n"
                   "}\n")
            findings = scan_p6(root)
        self.assertTrue(any(f.struct_type == "param" for f in findings))


if __name__ == "__main__":
    unittest.main()
