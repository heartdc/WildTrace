"""Core workbench tests — pure stdlib, runnable in the offline CI."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from ohvul.webapp_core import ScanManager, TriageStore, promote_case

FIXTURE = """
#include <string.h>

typedef struct { int a; int b; int c; } Widget;

int widget_sum(Widget *w) {
    return w->a + w->b + w->c;
}

int copy_into(char *out, const char *in, unsigned int len) {
    char stack[64];
    memcpy(stack, in, len);
    return stack[0] + out[0];
}
"""


def _make_tree(root: Path):
    (root / "ffi").mkdir(parents=True)
    (root / "ffi" / "sample_impl.c").write_text(FIXTURE, encoding="utf-8")


def _wait(job, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline and job.status not in ("done", "error"):
        time.sleep(0.05)
    return job.status


class TriageStoreTests(unittest.TestCase):
    def test_roundtrip_and_validation(self):
        with tempfile.TemporaryDirectory() as d:
            store = TriageStore(Path(d) / "t.json")
            self.assertEqual(store.get("s1", "f1")["status"], "open")
            rec = store.set("s1", "f1", "kept", "looks real")
            self.assertEqual(rec["status"], "kept")
            store2 = TriageStore(Path(d) / "t.json")
            self.assertEqual(store2.get("s1", "f1")["note"], "looks real")
            with self.assertRaises(ValueError):
                store.set("s1", "f1", "bogus")
            with self.assertRaises(ValueError):
                store.set("s1", "f1", "kept", "x" * 3000)
            with self.assertRaises(ValueError):
                store.set("bad id", "f1", "kept")
            self.assertEqual(store.for_scan("s1")["f1"]["status"], "kept")
            self.assertEqual(store.for_scan("other"), {})


class ScanManagerTests(unittest.TestCase):
    def test_scan_lifecycle_on_fixture_tree(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_tree(root / "target")
            mgr = ScanManager(root / "work")
            job = mgr.submit(root / "target")
            self.assertEqual(_wait(job), "done")
            self.assertFalse(job.error)
            self.assertTrue((job.output_dir / "findings.json").is_file())
            pub = job.public()
            self.assertIn("summary", pub)
            self.assertIn("surface", pub)
            self.assertTrue(any(p["phase"] == "layer" for p in pub["progress"]))
            self.assertTrue(any(p["phase"] == "report" for p in pub["progress"]))
            # rehydration from artifacts after "restart"
            sid = job.id
            mgr2 = ScanManager(root / "work")
            job2 = mgr2.get(sid)
            self.assertIsNotNone(job2)
            self.assertEqual(job2.status, "done")
            self.assertEqual(job2.findings(), job.findings())

    def test_submit_rejects_bad_input(self):
        with tempfile.TemporaryDirectory() as d:
            mgr = ScanManager(Path(d) / "w")
            with self.assertRaises(ValueError):
                mgr.submit(Path(d) / "nope")
            (Path(d) / "t").mkdir()
            with self.assertRaises(ValueError):
                mgr.submit(Path(d) / "t", min_confidence=999)


class PromoteCaseTests(unittest.TestCase):
    def test_skeleton_is_honest_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_tree(root / "target")
            mgr = ScanManager(root / "work")
            job = mgr.submit(root / "target")
            self.assertEqual(_wait(job), "done")
            findings = job.findings()
            if not findings:  # the fixture must yield at least one lead
                self.fail("fixture produced no findings for promotion test")
            f = findings[0]
            case_dir = promote_case(job, f["finding_id"], "foundation/demo",
                                    root / "cases")
            case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(case["schema"], "wildtrace-candidate-case-0.2")
            self.assertEqual(case["status"], "lead")
            self.assertFalse(case["confirmed_vulnerability"])
            self.assertEqual(case["next_gate"], "manual_review")
            self.assertIn("lead ≠ 漏洞", "".join(case["limitations"]))
            self.assertEqual(case["candidate"]["scan_id"], job.id)
            with self.assertRaises(ValueError):
                promote_case(job, f["finding_id"], "foundation/demo", root / "cases")
            with self.assertRaises(ValueError):
                promote_case(job, f["finding_id"], "no-slash", root / "cases")
            with self.assertRaises(ValueError):
                promote_case(job, "missing-id", "foundation/demo", root / "cases")


if __name__ == "__main__":
    unittest.main()
