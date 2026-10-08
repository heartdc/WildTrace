"""Local workbench core for the WildTrace webapp (pure stdlib).

ScanManager wraps ``autopilot.run`` as background jobs with progress and
log capture; TriageStore persists per-finding review state as JSON;
promote_case writes an honest, unreviewed case skeleton. Nothing here
touches the network or executes targets — the pipeline's local-only,
no-execution contract is the product.
"""
from __future__ import annotations

import io
import json
import re
import threading
import time
import uuid
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from pathlib import Path

from . import autopilot

TRIAGE_STATUSES = ("open", "kept", "false_positive", "promoted")
_SAFETY = {"local_only": True, "no_execution": True, "no_network": True}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_id(prefix: str) -> str:
    return prefix + "-" + uuid.uuid4().hex[:12]


def _relpath_str(root: Path, value: str) -> str:
    """Best-effort display path relative to the scanned root."""
    try:
        return str(Path(value).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return value.replace("\\", "/")


class ScanJob:
    def __init__(self, scan_id: str, source_root: Path, output_dir: Path,
                 min_confidence: int, joern: bool):
        self.id = scan_id
        self.source_root = source_root
        self.output_dir = output_dir
        self.min_confidence = min_confidence
        self.joern = joern
        self.status = "queued"          # queued|running|done|error
        self.created_at = _now()
        self.started_at = ""
        self.finished_at = ""
        self.error = ""
        self.report: dict | None = None
        self.progress: list[dict] = []  # [{phase, detail, at, elapsed}]
        self.log_lines: list[str] = []
        self._t0 = 0.0
        self._lock = threading.Lock()

    # -- worker helpers ----------------------------------------------------
    def emit(self, phase: str, detail: str = "") -> None:
        with self._lock:
            self.progress.append({"phase": phase, "detail": detail,
                                  "at": _now(),
                                  "elapsed": round(time.time() - self._t0, 1)})

    def log(self, line: str) -> None:
        with self._lock:
            self.log_lines.append(line)
            del self.log_lines[:-400]

    # -- views -------------------------------------------------------------
    def public(self) -> dict:
        with self._lock:
            elapsed = round(time.time() - self._t0, 1) if self._t0 and self.status == "running" else None
            return {
                "id": self.id, "status": self.status,
                "source_root": str(self.source_root),
                "min_confidence": self.min_confidence, "joern": self.joern,
                "created_at": self.created_at, "started_at": self.started_at,
                "finished_at": self.finished_at, "error": self.error,
                "elapsed": elapsed,
                "progress": list(self.progress[-40:]),
                "log_tail": list(self.log_lines[-60:]),
                "summary": (self.report or {}).get("summary"),
                "surface": (self.report or {}).get("surface"),
            }

    def findings(self) -> list[dict]:
        return list((self.report or {}).get("findings", []))


class ScanManager:
    """Background scan runner. One worker thread per job (local tool, low concurrency)."""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.scans_dir = self.workspace / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def submit(self, source_root: Path, *, min_confidence: int = 0,
               joern: bool = False) -> ScanJob:
        root = Path(source_root)
        if not root.is_dir():
            raise ValueError("source root must be an existing directory")
        if not 0 <= int(min_confidence) <= 100:
            raise ValueError("min_confidence must be in 0..100")
        scan_id = _safe_id("scan")
        out = self.scans_dir / scan_id
        job = ScanJob(scan_id, root, out, int(min_confidence), bool(joern))
        with self._lock:
            self._jobs[scan_id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run(self, job: ScanJob) -> None:
        job.status = "running"
        job.started_at = _now()
        job._t0 = time.time()
        job.log(f"scan start: {job.source_root} (min_confidence={job.min_confidence}, joern={job.joern})")
        buf_out, buf_err = io.StringIO(), io.StringIO()

        class _Tee(io.StringIO):
            def write(self, s):
                job.log(s.rstrip("\n")) if s.strip() else None
                return buf_err.write(s)

        try:
            with redirect_stdout(buf_out), redirect_stderr(_Tee()):
                job.report = autopilot.run(job.source_root, job.output_dir,
                                           job.min_confidence, joern=job.joern,
                                           progress=job.emit)
            job.status = "done"
            s = job.report.get("summary", {})
            job.log(f"scan done: {s.get('total', 0)} findings "
                    f"(H={s.get('high', 0)} M={s.get('medium', 0)}) "
                    f"in {job.report.get('elapsed_seconds')}s")
        except Exception as exc:  # surface, never crash the worker
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.log("scan error: " + job.error)
        finally:
            job.finished_at = _now()

    def get(self, scan_id: str) -> ScanJob | None:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is None:
            # process restart: rehydrate finished scans from artifacts
            report_path = self.scans_dir / scan_id / "findings.json"
            if report_path.is_file():
                try:
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return None
                meta = self._load_meta(scan_id)
                job = ScanJob(scan_id, Path(meta.get("source_root", "?")),
                              self.scans_dir / scan_id,
                              int(meta.get("min_confidence", 0)),
                              bool(meta.get("joern", False)))
                job.status = "done"
                job.report = report
                job.started_at = meta.get("started_at", "")
                job.finished_at = meta.get("finished_at", "")
                with self._lock:
                    self._jobs[scan_id] = job
            return job
        return job

    def _load_meta(self, scan_id: str) -> dict:
        p = self.scans_dir / scan_id / ".webmeta.json"
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def list_jobs(self) -> list[dict]:
        known = set()
        out = []
        with self._lock:
            jobs = list(self._jobs.values())
            known = {j.id for j in jobs}
        for j in sorted(jobs, key=lambda x: x.created_at, reverse=True):
            out.append(j.public())
        for report_path in sorted(self.scans_dir.glob("*/findings.json"), reverse=True):
            sid = report_path.parent.name
            if sid in known:
                continue
            j = self.get(sid)
            if j:
                out.append(j.public())
        return out


class TriageStore:
    """JSON-file persistence for per-finding review state, keyed scan_id+finding_id."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        tmp.replace(self.path)

    @staticmethod
    def _key(scan_id: str, finding_id: str) -> str:
        # finding ids embed source paths ("P4_ffi/impl.c_10" or with a
        # backslash on Windows); separators are inert in a dict key.
        if not re.fullmatch(r"[A-Za-z0-9_.\\/\-]{1,160}", scan_id + finding_id):
            raise ValueError("identifier contains unexpected characters")
        return scan_id + "/" + finding_id

    def get(self, scan_id: str, finding_id: str) -> dict:
        with self._lock:
            rec = self._data.get(self._key(scan_id, finding_id))
        if rec:
            return dict(rec)
        return {"status": "open", "note": "", "updated_at": ""}

    def set(self, scan_id: str, finding_id: str, status: str, note: str = "") -> dict:
        if status not in TRIAGE_STATUSES:
            raise ValueError("status must be one of " + ", ".join(TRIAGE_STATUSES))
        if len(note) > 2000:
            raise ValueError("note too long")
        rec = {"status": status, "note": note.strip(), "updated_at": _now()}
        with self._lock:
            self._data[self._key(scan_id, finding_id)] = rec
            self._save()
        return dict(rec)

    def for_scan(self, scan_id: str) -> dict[str, dict]:
        prefix = scan_id + "/"
        with self._lock:
            return {k[len(prefix):]: dict(v) for k, v in self._data.items()
                    if k.startswith(prefix)}


def promote_case(job: ScanJob, finding_id: str, component: str,
                 cases_root: Path) -> Path:
    """Write an honest, unreviewed case skeleton from one autopilot finding."""
    match = next((f for f in job.findings() if f.get("finding_id") == finding_id), None)
    if match is None:
        raise ValueError("finding not found in this scan")
    component = (component or "").strip()
    if not component or len(component) > 120 or "/" not in component:
        raise ValueError("component must look like a repo path, e.g. foundation/xyz")
    cases_root = Path(cases_root)
    cases_root.mkdir(parents=True, exist_ok=True)
    case_name = "weblead_" + re.sub(r"[^a-z0-9]+", "_", component.split("/")[-1].lower()) \
        + "_" + finding_id[-8:].lower()
    case_dir = cases_root / case_name
    if case_dir.exists():
        raise ValueError("case directory already exists: " + case_name)
    rel_file = _relpath_str(job.source_root, match.get("file", ""))
    case = {
        "schema": "wildtrace-candidate-case-0.2",
        "case_id": case_name,
        "component": component,
        "status": "lead",
        "cwe_candidate": [match["cwe"]] if match.get("cwe") else [],
        "confirmed_vulnerability": False,
        "candidate": {
            "source": rel_file,
            "lines": str(match.get("line", "")),
            "function": match.get("function", ""),
            "pattern": match.get("pattern", ""),
            "confidence": match.get("confidence", 0),
            "confidence_factors": match.get("confidence_factors", ""),
            "scan_id": job.id,
            "finding_id": finding_id,
        },
        "vulnerability": {"description": match.get("description", "")},
        "evidence_locations": {"source_file": rel_file,
                               "lines": str(match.get("line", ""))},
        "source_snippet": match.get("source_snippet", ""),
        "trigger_hint": match.get("trigger_hint", ""),
        "limitations": [
            "骨架由 WildTrace 本地工作台从扫描 lead 生成，未经人工复核。",
            "lead ≠ 漏洞：confidence 是模式启发式优先级，不是漏洞结论。",
            "升级路径：人工复核 → 源码等价复现 → 真库验证（T3 阶梯）。",
        ],
        "next_gate": "manual_review",
        "safety": dict(_SAFETY),
        "generated_by": "ohvul.webapp_core.promote_case",
        "generated_at": _now(),
    }
    case_dir.mkdir(parents=True)
    (case_dir / "case.json").write_text(
        json.dumps(case, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return case_dir
