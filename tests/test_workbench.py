"""Behavioral tests for the local web boundary, jobs, and evidence projection."""

import io
import json
import tempfile
import subprocess
import sys
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from ohvul.workbench.app import create_app

    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False

from ohvul.competition_report import project_case
from ohvul.impact_matrix import affected_range_verdict, evaluate_case
from ohvul.workbench.data import digest, normalize_findings, source_context
from ohvul.workbench.store import Store
from ohvul.workbench.triage import build as build_triage


class EvidenceRegressionTests(unittest.TestCase):
    def test_triage_groups_without_suppressing_candidates(self):
        rows = [
            {
                "id": "a",
                "file": "src/a.c",
                "line": 10,
                "rule": "P6_null_deref",
                "cwe": "CWE-476",
                "function": "f",
                "source_sha256": "a" * 64,
            },
            {
                "id": "b",
                "file": "src/a.c",
                "line": 12,
                "rule": "P6_null_deref",
                "cwe": "CWE-476",
                "function": "f",
                "source_sha256": "a" * 64,
            },
            {
                "id": "c",
                "file": "tests/a.c",
                "line": 2,
                "rule": "P6_null_deref",
                "cwe": "CWE-476",
                "function": "f",
                "source_sha256": "a" * 64,
            },
        ]
        queue = build_triage(rows)
        self.assertEqual(queue["candidate_count"], 3)
        self.assertEqual(queue["group_count"], 2)
        self.assertEqual(sum(queue["lane_counts"].values()), 2)
        self.assertEqual(queue["confirmed_vulnerabilities"], 0)

    def test_negative_states_never_become_positive(self):
        result = project_case(
            {
                "runtime_status": "failed",
                "product_reachability": "unknown",
                "submission": {"official_status": "rejected"},
            },
            "test",
        )
        self.assertFalse(result["evidence_dimensions"]["official_acceptance"])
        self.assertFalse(result["evidence_dimensions"]["product_impact"])
        self.assertFalse(
            result["evidence_dimensions"]["equivalent_or_runtime_reproduction"]
        )

    def test_disjoint_ranges_and_inclusive_endpoint(self):
        ranges = [
            {
                "versions": [
                    {"version": "1.0", "lessThanOrEqual": "2.0", "status": "affected"},
                    {"version": "3.0", "lessThan": "4.0", "status": "affected"},
                ]
            }
        ]
        self.assertEqual(affected_range_verdict(ranges, "2.0"), "affected")
        self.assertEqual(affected_range_verdict(ranges, "2.5"), "unknown")
        self.assertEqual(affected_range_verdict(ranges, "4.0"), "unknown")

    def test_native_and_same_version_require_branch_evidence(self):
        for record in (
            {"component": "base/example"},
            {"component": "third_party/cjson", "observed_version": "1.7.19"},
        ):
            self.assertEqual(
                set(evaluate_case(record)["branches"].values()), {"unknown"}
            )
        record = {
            "component": "base/example",
            "branch_evidence": {
                "master": {
                    "verdict": "affected",
                    "source_commit": "a" * 40,
                    "reference": "local-run.json",
                }
            },
        }
        self.assertEqual(
            evaluate_case(record, strict_evidence=True)["branches"]["master"],
            "affected",
        )

    def test_restart_marks_inflight_tasks_interrupted(self):
        with tempfile.TemporaryDirectory() as d:
            first = Store(d)
            first.put({"id": "queued", "status": "queued"})
            first.db.close()
            second = Store(d)
            self.assertEqual(second.task("queued")["status"], "interrupted")
            second.db.close()


@unittest.skipUnless(WEB_AVAILABLE, "Install wildtrace[workbench] for web tests")
class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "sample.c").write_text(
            "void audit(char *arg) { arg[0] = arg[1] + arg[2]; }\n", encoding="utf-8"
        )
        self.app = create_app(self.root / "state")
        self.client = TestClient(self.app, headers={"X-Workbench": "1"})
        self.client.__enter__()
        self.client.put(
            "/api/settings",
            json={
                "source_roots": [str(self.source)],
                "distribution": "Ubuntu",
                "timeout": 30,
            },
        )

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def wait(self, tid):
        for _ in range(200):
            task = self.client.get("/api/tasks/" + tid).json()
            if task["status"] in ("completed", "failed", "cancelled"):
                return task
            time.sleep(0.05)
        self.fail("Task did not finish")

    def seed(self):
        folder = self.root / "state" / "tasks" / "seed"
        folder.mkdir(parents=True)
        self.app.state.store.put(
            {
                "id": "seed",
                "status": "completed",
                "kind": "scan",
                "folder": str(folder),
                "params": {"source_root": str(self.source)},
            }
        )
        result = {
            "status": "completed",
            "source_hashes": {"sample.c": digest(self.source / "sample.c")},
            "findings": [
                {
                    "finding_id": "one",
                    "file": "sample.c",
                    "line": 1,
                    "pattern": "P6",
                    "cwe": "CWE-476",
                    "function": "audit",
                    "description": "candidate",
                }
            ],
        }
        (folder / "result.json").write_text(json.dumps(result), encoding="utf-8")
        return self.client.get("/api/findings").json()[0]["id"]

    def test_real_scan_worker_and_sse_resume(self):
        r = self.client.post(
            "/api/tasks/scan",
            json={"source_root": str(self.source), "mode": "autopilot"},
        )
        self.assertEqual(r.status_code, 200)
        tid = r.json()["id"]
        task = self.wait(tid)
        self.assertEqual(task["status"], "completed", task)
        stream = self.client.get("/api/tasks/" + tid + "/events").text
        self.assertIn("event: done", stream)
        events = self.app.state.store.events(tid)
        resumed = self.client.get(
            "/api/tasks/" + tid + "/events",
            headers={"Last-Event-ID": str(events[-1]["id"])},
        ).text
        self.assertNotIn("event: log", resumed)

    def test_invalid_source_and_host_origin_are_blocked(self):
        for root in (self.source / "missing", self.root):
            self.assertEqual(
                self.client.post(
                    "/api/tasks/scan", json={"source_root": str(root)}
                ).status_code,
                400,
            )
        self.assertEqual(
            self.client.get(
                "/api/health", headers={"Host": "evil.example"}
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/tasks/scan", json={}, headers={"Origin": "https://evil.example"}
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/tasks/scan", json={}, headers={"X-Workbench": "0"}
            ).status_code,
            403,
        )

    def test_case_assets_and_complete_report_flags(self):
        cases = self.client.get("/api/cases").json()
        self.assertEqual(len(cases), 19)
        self.assertTrue(all(c["description"] != "见 case.json" for c in cases))
        hi = next(c for c in cases if c["id"] == "hiappevent_ffi_watcher_null_filter")
        self.assertTrue(
            any(a["name"] == "hiappevent_null_watcher.c" for a in hi["assets"])
        )
        body = {"case_ids": [hi["id"]], "format": "preview"}
        report = self.client.post("/api/reports", json=body).json()
        self.assertFalse(report["complete"])
        self.assertIn("固定版本源码片段", report["missing"][hi["id"]])
        archive = self.client.post("/api/reports", json={**body, "format": "zip"})
        with zipfile.ZipFile(io.BytesIO(archive.content)) as z:
            self.assertIn("manifest.json", z.namelist())
            self.assertTrue(any("hiappevent_null_watcher.c" in p for p in z.namelist()))
        self.assertEqual(
            self.client.get(
                "/api/assets", params={"path": "../SECURITY.md"}
            ).status_code,
            400,
        )

    def test_review_is_append_only_and_not_a_verdict(self):
        fid = self.seed()
        for decision in ("approved_for_verification", "rejected_candidate"):
            self.assertEqual(
                self.client.post(
                    "/api/reviews/" + fid,
                    json={"decision": decision, "reviewer": "tester", "note": "test"},
                ).status_code,
                200,
            )
        item = self.client.get("/api/findings/" + fid).json()
        self.assertEqual(len(item["reviews"]), 2)
        self.assertNotIn("confirmed_vulnerability", item)

    def test_key_never_echoes_or_persists_and_preview_is_bound(self):
        fid = self.seed()
        body = {
            "base_url": "https://api.z.ai/api/anthropic",
            "model": "glm-5.3",
            "api_key": "PRIVATE-KEY-TEST",
        }
        result = self.client.put("/api/model/connection", json=body)
        self.assertNotIn(body["api_key"], result.text)
        plan = self.client.post(
            "/api/model/preview", json={"finding_ids": [fid]}
        ).json()
        self.assertIn("messages", plan["items"][0])
        (self.source / "sample.c").write_text("changed", encoding="utf-8")
        result = self.client.post(
            "/api/model/run",
            json={"finding_ids": [fid], "preview_sha256": plan["preview_sha256"]},
        )
        self.assertEqual(result.status_code, 400)
        self.client.delete("/api/model/connection/key")
        self.assertFalse(self.client.get("/api/model/connection").json()["has_key"])
        for p in (self.root / "state").rglob("*"):
            if p.is_file():
                self.assertNotIn(body["api_key"].encode(), p.read_bytes())

    def test_source_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            source_context(self.source, {"file": "../outside.c", "line": 1})

    def test_project_selection_and_native_scope_snapshot(self):
        from ohvul.workbench.project_scan import prepare, verify

        (self.source / "build").mkdir()
        (self.source / "build" / "generated.c").write_text("int generated;")
        response = self.client.post(
            "/api/projects",
            json={
                "name": "Source project",
                "root": str(self.source),
                "include": ["sample.c"],
                "exclude": ["build"],
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        project = response.json()
        listing = self.client.get(f"/api/projects/{project['id']}/browse").json()
        self.assertTrue(any(e["name"] == "sample.c" for e in listing["entries"]))
        self.assertEqual(
            self.client.get(
                f"/api/projects/{project['id']}/browse", params={"path": ".."}
            ).status_code,
            400,
        )
        folder = self.root / "scope"
        folder.mkdir()
        copied, manifest = prepare(project, folder)
        self.assertEqual([r["file"] for r in manifest["files"]], ["sample.c"])
        self.assertFalse((copied / "build").exists())
        verify(manifest)
        (self.source / "sample.c").write_text("changed")
        with self.assertRaises(ValueError):
            verify(manifest)

    def test_versioned_case_capture_links_and_export(self):
        fid = self.seed()
        for args in (
            ["init"],
            ["add", "."],
            [
                "-c",
                "user.name=Workbench Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "Fixture",
            ],
        ):
            subprocess.run(
                ["git", "-C", str(self.source), *args], check=True, capture_output=True
            )
        project = self.client.post(
            "/api/projects", json={"name": "Pinned source", "root": str(self.source)}
        ).json()
        created = self.client.post(
            "/api/cases", json={"finding_id": fid, "author": "tester"}
        ).json()
        cid = created["id"]
        self.assertEqual(created["revision"], 1)
        captured = self.client.post(
            f"/api/cases/{cid}/capture",
            json={
                "revision": 1,
                "project_id": project["id"],
                "file": "sample.c",
                "start": 1,
                "end": 1,
                "author": "tester",
            },
        )
        self.assertEqual(captured.status_code, 200, captured.text)
        self.assertNotIn("固定版本源码片段", captured.json()["missing"])
        updated = self.client.put(
            f"/api/cases/{cid}",
            json={
                "revision": 2,
                "author": "tester",
                "fields": {
                    "description": "Updated description",
                    "reproduction_commands": "See attached record",
                },
            },
        )
        self.assertEqual(updated.json()["revision"], 3)
        conflict = self.client.put(
            f"/api/cases/{cid}",
            json={
                "revision": 2,
                "author": "tester",
                "fields": {"description": "stale"},
            },
        )
        self.assertEqual(conflict.status_code, 400)
        old = self.client.get(f"/api/cases/{cid}?revision=1").json()
        self.assertNotEqual(old["description"], "Updated description")
        report = self.client.post(
            "/api/reports", json={"case_ids": [cid], "revisions": {cid: 2}}
        ).json()
        self.assertEqual(report["cases"][0]["revision"], 2)
        self.assertIn("seed", [t["id"] for t in report["tasks"]])
        self.assertNotIn("Updated description", report["markdown"])
        archive = self.client.post(
            "/api/reports", json={"case_ids": [cid], "format": "zip"}
        )
        with zipfile.ZipFile(io.BytesIO(archive.content)) as z:
            self.assertTrue(any("source_snippet_" in p for p in z.namelist()))
        self.assertEqual(
            self.client.get("/api/findings/" + fid).json()["linked_cases"][0]["id"], cid
        )

    def test_attachment_digest_and_case_conflict(self):
        fid = self.seed()
        case = self.client.post(
            "/api/cases", json={"finding_id": fid, "author": "tester"}
        ).json()
        body = {
            "revision": 1,
            "author": "tester",
            "name": "notes.txt",
            "role": "document",
            "text": "Local notes",
        }
        updated = self.client.post(
            f"/api/cases/{case['id']}/attachments", json=body
        ).json()
        asset = updated["assets"][-1]
        response = self.client.get(
            f"/api/cases/{case['id']}/attachment",
            params={"asset_id": asset["asset_id"]},
        )
        self.assertEqual(response.text, "Local notes")
        (self.root / "state" / "case-blobs" / asset["asset_id"]).write_text("modified")
        self.assertEqual(
            self.client.get(
                f"/api/cases/{case['id']}/attachment",
                params={"asset_id": asset["asset_id"]},
            ).status_code,
            400,
        )
        latest = self.client.get(f"/api/cases/{case['id']}").json()
        self.assertIn("附件缺失或摘要不匹配", latest["missing"])

    def test_missing_source_is_visible_and_builtin_digest_is_bound(self):
        fid = self.seed()
        (self.source / "sample.c").unlink()
        self.source.rmdir()
        item = self.client.get("/api/findings/" + fid).json()
        self.assertEqual(item["source"]["status"], "missing")
        result = {
            "findings": [
                {
                    "alert_id": "a",
                    "location": {"file": "a.c", "line": 1},
                    "evidence": {"file_sha256": "a" * 64},
                }
            ]
        }
        self.assertEqual(
            normalize_findings(result, "test")[0]["source_sha256"], "a" * 64
        )

    def test_cancellation_of_queued_job(self):
        with patch.object(self.app.state.jobs.queue, "put"):
            task = self.app.state.jobs.create(
                "scan", {"source_root": str(self.source), "mode": "autopilot"}
            )
        self.assertEqual(
            self.client.post("/api/tasks/" + task["id"] + "/cancel").json()["status"],
            "cancelled",
        )

    def test_cancellation_terminates_running_worker(self):
        original = subprocess.Popen

        def slow_process(args, **kwargs):
            if args[0] != sys.executable:
                return original(args, **kwargs)
            return original(
                [
                    sys.executable,
                    "-u",
                    "-c",
                    'import sys,time;sys.stdin.readline();print("ready",flush=True);time.sleep(30)',
                ],
                **kwargs,
            )

        with patch("ohvul.workbench.jobs.subprocess.Popen", side_effect=slow_process):
            task = self.app.state.jobs.create(
                "scan", {"source_root": str(self.source), "mode": "autopilot"}
            )
            for _ in range(100):
                if self.app.state.jobs.current:
                    break
                time.sleep(0.02)
            process = self.app.state.jobs.current[1]
            self.client.post("/api/tasks/" + task["id"] + "/cancel")
            self.assertEqual(self.wait(task["id"])["status"], "cancelled")
            self.assertIsNotNone(process.poll())

    def test_autopilot_failure_is_not_a_successful_empty_scan(self):
        from ohvul.autopilot import run

        with patch(
            "ohvul.autopilot.SCANNERS",
            [("P4", lambda root: (_ for _ in ()).throw(OSError("read failed")), "gen")],
        ):
            result = run(self.source, self.root / "failed-scan")
        self.assertEqual(result["status"], "partial")
        self.assertNotIn("P4", result["summary"]["scanners"])
        self.assertTrue(result["input_errors"])

    def test_model_success_timeout_refusal_and_truncation(self):
        from ohvul.workbench.worker import run
        from ohvul.llm_adapter import LlmTransportError

        fid = self.seed()
        for outcome in ("success", "timeout", "refusal", "truncation"):
            folder = self.root / outcome
            folder.mkdir()
            plan = self.client.post(
                "/api/model/preview", json={"finding_ids": [fid]}
            ).json()
            (folder / "job.json").write_text(
                json.dumps({"kind": "model", "params": plan}), encoding="utf-8"
            )
            response = {
                "content": "Review suggestion",
                "finish_reason": "length" if outcome == "truncation" else "stop",
            }
            with patch(
                "ohvul.llm_adapter.chat_completion",
                side_effect=(
                    LlmTransportError(outcome)
                    if outcome in ("timeout", "refusal")
                    else None
                ),
                return_value=response,
            ) as transport:
                if outcome == "success":
                    run(folder, "PRIVATE-KEY-TEST")
                    self.assertEqual(
                        json.loads((folder / "result.json").read_text())["results"][0][
                            "status"
                        ],
                        "suggestion",
                    )
                else:
                    with self.assertRaises((ValueError, LlmTransportError)):
                        run(folder, "PRIVATE-KEY-TEST")
                self.assertEqual(transport.call_count, 1)
                self.assertEqual(
                    transport.call_args.args[0], plan["items"][0]["messages"]
                )


if __name__ == "__main__":
    unittest.main()
