from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from .data import ROOT, read_json, source_context
from .jobs import linux_path


def save(folder, value):
    (folder / "result.json").write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def profile_argument(value: str, flag: str) -> list:
    """Validate an analysis-profile path once, for both the API endpoint
    and the worker's CLI argv (kept here: the worker must not import the
    web app — WSL project scans run without web deps)."""
    if not value:
        return []
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ValueError(f"{flag} 指向的 profile 文件不存在: {value}")
    return [flag, str(path)]


def cjson(folder, params):
    from tools import cjson_case

    (folder / "wsl.pid").write_text(str(os.getpgrp()))
    output = folder / "verification"
    print("STAGE 校验源码指纹并准备独立副本", flush=True)
    cjson_case.prepare(Path(params["source_root"]), output)
    print("STAGE 隔离检查、编译与原版 / 补丁版运行矩阵", flush=True)
    observed = cjson_case.execute(output, True)
    print("STAGE 离线核验运行记录", flush=True)
    cjson_case.verify_runtime(output)
    save(folder, observed)


def run(folder, secret):
    job = read_json(folder / "job.json")
    params, kind = job["params"], job["kind"]
    if kind == "scan":
        project = params.get("project")
        if project and project["environment"] == "wsl" and os.name == "nt":
            print("STAGE 在 WSL 内启动项目扫描", flush=True)
            rc = subprocess.call(
                [
                    "wsl",
                    "-d",
                    project["distribution"],
                    "--cd",
                    linux_path(ROOT),
                    "--",
                    "setsid",
                    "--wait",
                    "python3",
                    "-u",
                    "-m",
                    "ohvul.workbench.worker",
                    linux_path(folder),
                    "--project-scan",
                ],
                stdin=subprocess.DEVNULL,
            )
            if rc:
                raise ValueError("WSL 项目扫描未完成；查看保留日志")
            return
        manifest = None
        root = Path(params["source_root"])
        if project:
            from .project_scan import prepare, verify

            print("STAGE 固定项目选择范围与源码摘要", flush=True)
            root, manifest = prepare(project, folder)
        print("STAGE 扫描源码", flush=True)
        if params["mode"] == "autopilot":
            from ohvul.autopilot import run as scan

            # Gap-A wiring: joern is an opt-in autopilot layer — it skips
            # with a warning when /opt/joern is unavailable, so passing the
            # user's choice through is always safe (previously the workbench
            # never set it and UI scans were rules-only).
            result = scan(
                root,
                folder / "scan",
                params.get("min_confidence", 0),
                joern=bool(params.get("joern")),
            )
            save(folder, result)
            if result["status"] != "completed":
                raise ValueError("Scan incomplete")
        else:
            from ohvul.cli import main

            output = folder / "result.json"
            sys.argv = [
                "ohvul",
                str(root),
                "--output",
                str(output),
                "--report-output",
                str(folder / "audit-report.json"),
            ]
            # Gap-A wiring: engine/compiler profiles enable the WSL Clang
            # engine and Clang AST/typed-memory analysis layers that the
            # plain CLI path otherwise never runs (mentor review 2026-10).
            sys.argv += profile_argument(params.get("engine_profile", ""),
                                         "--engine-profile")
            sys.argv += profile_argument(params.get("compiler_profile", ""),
                                         "--compiler-profile")
            main()
        if manifest:
            print("STAGE 核对项目源码与扫描输入", flush=True)
            verify(manifest)
        print("STAGE 扫描结果已保存", flush=True)
    elif kind == "model":
        from ohvul.llm_adapter import chat_completion
        from ohvul.llm_poc import _extract_code_block, _validate_poc

        results = []
        for item in params["items"]:
            current = source_context(params["source_root"], item)
            if current.get("sha256") != item["context"]["sha256"]:
                raise ValueError("Source changed after model preview")
            print("STAGE 模型处理 " + item["id"], flush=True)
            settings = {**params["connection"], "api_key": secret}
            result = chat_completion(item["messages"], **settings, json_mode=False)
            if secret and secret in json.dumps(result, ensure_ascii=False):
                raise ValueError(
                    "Provider response contained credential; not persisted"
                )
            if result.get("finish_reason") == "length":
                save(
                    folder,
                    {
                        "results": results,
                        "status": "partial",
                        "error": "response_truncated",
                    },
                )
                raise ValueError("response_truncated")
            if params["action"] == "poc":
                code = _extract_code_block(result.get("content", ""))
                valid, note = _validate_poc(code or "", item)
                result["code"] = code
                result["structural_check"] = {"passed": valid, "note": note}
                result["status"] = "draft"
                result["compiled"] = False
                result["executed"] = False
            else:
                result["status"] = "suggestion"
            results.append({"finding_id": item["id"], **result})
            save(
                folder,
                {
                    "status": "completed",
                    "results": results,
                    "confirmed_vulnerabilities": 0,
                },
            )
    elif kind == "cjson":
        if os.name == "nt":
            print("STAGE 启动 WSL 隔离验证", flush=True)
            args = [
                "wsl",
                "-d",
                params["distribution"],
                "--cd",
                linux_path(ROOT),
                "--",
                "setsid",
                "--wait",
                "python3",
                "-u",
                "-m",
                "ohvul.workbench.worker",
                linux_path(folder),
                "--cjson",
            ]
            rc = subprocess.call(args, stdin=subprocess.DEVNULL)
            if rc:
                raise ValueError("WSL verification failed; no host fallback")
        else:
            cjson(folder, params)


def main():
    folder = Path(sys.argv[1]).resolve()
    secret = ""
    try:
        if "--cjson" in sys.argv:
            cjson(folder, read_json(folder / "job.json")["params"])
        elif "--project-scan" in sys.argv:
            (folder / "wsl.pid").write_text(str(os.getpgrp()))
            run(folder, "")
        else:
            secret = json.loads(sys.stdin.readline()).get("key", "")
            run(folder, secret)
        return 0
    except Exception as exc:
        message = str(exc).replace(secret, "[REDACTED]") if secret else str(exc)
        result_file = folder / "result.json"
        if read_json(folder / "job.json")["kind"] == "model" and result_file.is_file():
            result = read_json(result_file)
            result.update(status="partial", error=message[:2000])
            save(folder, result)
        print("ERROR " + message[:2000], flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
