"""FastAPI layer for the WildTrace local workbench.

Binds 127.0.0.1 only. FastAPI/uvicorn are local conveniences and are
imported lazily so the rest of ohvul (and CI) never depends on them.
"""
from __future__ import annotations

import json
from pathlib import Path

from .webapp_core import ScanManager, TriageStore, TRIAGE_STATUSES, promote_case

try:  # local convenience only; tests skip when absent
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - exercised implicitly on CI
    FastAPI = HTTPException = StaticFiles = BaseModel = None


class ScanRequest(BaseModel):
    source_root: str
    min_confidence: int = 0
    joern: bool = False


class TriageRequest(BaseModel):
    status: str
    note: str = ""


class PromoteRequest(BaseModel):
    finding_id: str
    component: str


def create_app(workdir: Path, cases_root: Path | None = None,
               static_dir: Path | None = None) -> "FastAPI":
    if FastAPI is None:
        raise RuntimeError("fastapi is not installed; pip install fastapi uvicorn")
    workdir = Path(workdir)
    manager = ScanManager(workdir)
    triage = TriageStore(workdir / "triage.json")
    cases_root = Path(cases_root) if cases_root else workdir / "cases"
    static_dir = Path(static_dir) if static_dir else None

    app = FastAPI(title="WildTrace 本地工作台", version="0.1",
                  docs_url=None, redoc_url=None)

    @app.get("/api/meta")
    def meta():
        return {"tool": "WildTrace", "safety": {"local_only": True,
                                                "no_execution": True,
                                                "no_network": True},
                "triage_statuses": list(TRIAGE_STATUSES),
                "workspace": str(workdir)}

    @app.get("/api/scans")
    def list_scans():
        return {"scans": manager.list_jobs()}

    @app.post("/api/scans")
    def start_scan(req: ScanRequest):
        try:
            job = manager.submit(Path(req.source_root),
                                 min_confidence=req.min_confidence,
                                 joern=req.joern)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"scan_id": job.id}

    @app.get("/api/scans/{scan_id}")
    def scan_status(scan_id: str):
        job = manager.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return job.public()

    @app.get("/api/scans/{scan_id}/findings")
    def scan_findings(scan_id: str, status: str = "", severity: str = "",
                      pattern: str = "", cwe: str = "", q: str = "",
                      min_conf: int = 0, page: int = 1, size: int = 50):
        job = manager.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        size = max(1, min(size, 200))
        page = max(1, page)
        tmap = triage.for_scan(scan_id)

        def tstat(f):
            return tmap.get(f.get("finding_id", ""), {}).get("status", "open")

        rows = job.findings()
        if status:
            rows = [f for f in rows if tstat(f) == status]
        if severity:
            rows = [f for f in rows if f.get("severity") == severity]
        if pattern:
            rows = [f for f in rows if pattern.lower() in f.get("pattern", "").lower()]
        if cwe:
            rows = [f for f in rows if cwe.lower() in f.get("cwe", "").lower()]
        if q:
            needle = q.lower()
            rows = [f for f in rows if needle in f.get("file", "").lower()
                    or needle in f.get("function", "").lower()
                    or needle in f.get("description", "").lower()]
        rows = [f for f in rows if f.get("confidence", 0) >= min_conf]
        total = len(rows)
        rows = rows[(page - 1) * size: page * size]
        items = []
        for f in rows:
            item = dict(f)
            item["triage"] = tmap.get(f.get("finding_id", ""),
                                      {"status": "open", "note": "", "updated_at": ""})
            items.append(item)
        return {"total": total, "page": page, "size": size, "items": items}

    @app.patch("/api/scans/{scan_id}/findings/{finding_id}")
    def update_finding(scan_id: str, finding_id: str, req: TriageRequest):
        job = manager.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if not any(f.get("finding_id") == finding_id for f in job.findings()):
            raise HTTPException(status_code=404, detail="finding not found")
        try:
            rec = triage.set(scan_id, finding_id, req.status, req.note)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return rec

    @app.post("/api/scans/{scan_id}/promote")
    def promote(scan_id: str, req: PromoteRequest):
        job = manager.get(scan_id)
        if job is None or job.status != "done":
            raise HTTPException(status_code=404, detail="finished scan not found")
        try:
            case_dir = promote_case(job, req.finding_id, req.component, cases_root)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        triage.set(scan_id, req.finding_id, "promoted",
                   triage.get(scan_id, req.finding_id).get("note", ""))
        return {"case_dir": str(case_dir)}

    @app.get("/api/scans/{scan_id}/artifacts")
    def artifacts(scan_id: str):
        job = manager.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        out = []
        for p in sorted(job.output_dir.rglob("*")):
            if p.is_file() and p.stat().st_size < 2 * 1024 * 1024:
                out.append({"path": p.relative_to(job.output_dir).as_posix(),
                            "bytes": p.stat().st_size})
        return {"artifacts": out}

    @app.get("/api/scans/{scan_id}/artifacts/{rest_of_path:path}")
    def artifact_content(scan_id: str, rest_of_path: str):
        job = manager.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        target = (job.output_dir / rest_of_path).resolve()
        if not target.is_relative_to(job.output_dir.resolve()) or not target.is_file():
            raise HTTPException(status_code=404, detail="artifact not found")
        media = {".md": "text/markdown", ".json": "application/json",
                 ".c": "text/plain", ".txt": "text/plain"}
        suffix = target.suffix.lower()
        if suffix in (".md", ".json", ".c", ".txt"):
            return JSONResponse({"path": rest_of_path,
                                 "content": target.read_text(encoding="utf-8",
                                                             errors="replace")})
        return FileResponse(target)

    if static_dir is not None and (static_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="web")
    else:
        @app.get("/")
        def root_hint():
            return {"hint": "frontend not built; run `npm run build` in web/ "
                            "or use the API under /api"}

    @app.exception_handler(ValueError)
    async def value_error_handler(request, exc):  # pragma: no cover
        return JSONResponse({"detail": str(exc)}, status_code=400)

    return app


def main():
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=Path(".webwork"))
    parser.add_argument("--cases", type=Path, default=None)
    parser.add_argument("--static", type=Path, default=None)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    static = args.static or Path(__file__).resolve().parent.parent / "web" / "dist"
    cases = args.cases or (Path(__file__).resolve().parent.parent / "webcases")
    app = create_app(args.workdir, cases_root=cases, static_dir=static)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
