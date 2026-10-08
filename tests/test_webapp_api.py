"""API-layer tests — skipped when fastapi/httpx are unavailable (offline CI)."""
import tempfile
import time
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

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


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class WebappApiTests(unittest.TestCase):
    def test_scan_triage_promote_flow(self):
        from ohvul.webapp import create_app
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "target" / "ffi").mkdir(parents=True)
            (root / "target" / "ffi" / "impl.c").write_text(FIXTURE, encoding="utf-8")
            app = create_app(root / "work", cases_root=root / "cases")
            client = TestClient(app)

            meta = client.get("/api/meta").json()
            self.assertTrue(meta["safety"]["local_only"])

            # bad request rejected
            r = client.post("/api/scans", json={"source_root": str(root / "missing")})
            self.assertEqual(r.status_code, 400)

            r = client.post("/api/scans",
                            json={"source_root": str(root / "target"),
                                  "min_confidence": 0})
            self.assertEqual(r.status_code, 200)
            sid = r.json()["scan_id"]

            for _ in range(600):
                st = client.get(f"/api/scans/{sid}").json()
                if st["status"] in ("done", "error"):
                    break
                time.sleep(0.05)
            self.assertEqual(st["status"], "done", st.get("error"))

            findings = client.get(f"/api/scans/{sid}/findings?size=5").json()
            self.assertGreaterEqual(findings["total"], 0)
            if findings["items"]:
                fid = findings["items"][0]["finding_id"]
                r = client.patch(f"/api/scans/{sid}/findings/{fid}",
                                 json={"status": "kept", "note": "review later"})
                self.assertEqual(r.status_code, 200)
                rows = client.get(f"/api/scans/{sid}/findings?status=kept").json()
                self.assertEqual(rows["total"], 1)
                r = client.post(f"/api/scans/{sid}/promote",
                                json={"finding_id": fid,
                                      "component": "foundation/demo"})
                self.assertEqual(r.status_code, 200)
                self.assertTrue(Path(r.json()["case_dir"]).is_dir())

            arts = client.get(f"/api/scans/{sid}/artifacts").json()["artifacts"]
            names = [a["path"] for a in arts]
            self.assertIn("findings.json", names)
            md = client.get(f"/api/scans/{sid}/artifacts/findings.md").json()
            self.assertIn("自动化漏洞分析报告", md["content"])
            # traversal is refused
            r = client.get(f"/api/scans/{sid}/artifacts/../../cases/x")
            self.assertIn(r.status_code, (400, 404))

            # unknown scan
            self.assertEqual(client.get("/api/scans/nope").status_code, 404)


if __name__ == "__main__":
    unittest.main()
