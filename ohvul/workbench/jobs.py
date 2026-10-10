from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from .data import ROOT
from .store import now

TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def linux_path(path):
    value = str(Path(path).resolve())
    if len(value) > 2 and value[1] == ":":
        return "/mnt/" + value[0].lower() + "/" + value[3:].replace("\\", "/")
    return value


class Jobs:
    def __init__(self, store):
        self.store = store
        self.queue = queue.Queue()
        self.secrets = {}
        self.lock = threading.RLock()
        self.current = None
        self.closed = False
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def create(self, kind, params, secret=None):
        tid = uuid.uuid4().hex
        folder = self.store.root / "tasks" / tid
        folder.mkdir(parents=True)
        task = {
            "id": tid,
            "kind": kind,
            "status": "queued",
            "params": params,
            "created_at": now(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "exit_code": None,
            "stage": "等待执行",
            "folder": str(folder),
        }
        (folder / "job.json").write_text(
            json.dumps(task, ensure_ascii=False), encoding="utf-8"
        )
        self.store.put(task)
        if secret:
            self.secrets[tid] = secret
        self.store.event(tid, "任务进入串行队列")
        self.queue.put(tid)
        return task

    def cancel(self, tid):
        with self.lock:
            task = self.store.task(tid)
            if task["status"] in TERMINAL:
                return task
            self.store.update(tid, status="cancelling")
            if self.current and self.current[0] == tid:
                self.kill(task, self.current[1])
            else:
                self.store.update(
                    tid, status="cancelled", finished_at=now(), stage="已取消"
                )
            self.secrets.pop(tid, None)
        return self.store.task(tid)

    def kill(self, task, process):
        # WSL children are a separate process group, outside taskkill's tree.
        pid_file = Path(task["folder"]) / "wsl.pid"
        if (
            task["kind"] == "cjson"
            or task["params"].get("project", {}).get("environment") == "wsl"
        ) and pid_file.is_file():
            pid = pid_file.read_text().strip()
            if pid.isdigit():
                try:
                    subprocess.run(
                        [
                            "wsl",
                            "-d",
                            task["params"]["distribution"],
                            "--",
                            "/bin/kill",
                            "-TERM",
                            "--",
                            "-" + pid,
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=15,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    self.store.event(
                        task["id"], "WSL 进程组清理未确认；请检查隔离进程状态"
                    )
        if process.poll() is None:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            else:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def loop(self):
        while True:
            tid = self.queue.get()
            if tid is None:
                return
            task = self.store.task(tid)
            with self.lock:
                if self.closed or task["status"] != "queued":
                    continue
                self.store.update(
                    tid, status="running", started_at=now(), stage="执行中"
                )
                env = {
                    k: v
                    for k, v in os.environ.items()
                    if not any(s in k.upper() for s in ("API_KEY", "TOKEN", "SECRET"))
                }
                env["PYTHONUTF8"] = "1"
                try:
                    process = subprocess.Popen(
                        [
                            sys.executable,
                            "-u",
                            "-m",
                            "ohvul.workbench.worker",
                            task["folder"],
                        ],
                        cwd=ROOT,
                        env=env,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        start_new_session=os.name != "nt",
                        creationflags=(
                            subprocess.CREATE_NEW_PROCESS_GROUP
                            if os.name == "nt"
                            else 0
                        ),
                    )
                    self.current = (tid, process)
                except OSError as exc:
                    self.store.update(
                        tid, status="failed", error=str(exc), finished_at=now()
                    )
                    self.secrets.pop(tid, None)
                    continue
            secret = self.secrets.pop(tid, "")
            timer = threading.Timer(
                task["params"].get("timeout", 1800), lambda: self.timeout(tid, process)
            )
            timer.start()
            try:
                process.stdin.write(json.dumps({"key": secret}) + "\n")
                process.stdin.close()
                size = 0
                with (Path(task["folder"]) / "task.log").open(
                    "w", encoding="utf-8"
                ) as log:
                    for line in iter(process.stdout.readline, ""):
                        if secret:
                            line = line.replace(secret, "[REDACTED]")
                        size += len(line.encode("utf-8"))
                        if size > 2 * 1024 * 1024:
                            self.store.event(tid, "日志超过 2 MiB 上限，任务已停止")
                            self.kill(task, process)
                            break
                        log.write(line)
                        log.flush()
                        self.store.event(tid, line.rstrip())
                        if line.startswith("STAGE "):
                            self.store.update(tid, stage=line[6:].strip())
                code = process.wait(timeout=20)
                result = Path(task["folder"]) / "result.json"
                state = self.store.task(tid)
                status = (
                    "cancelled"
                    if state["status"] == "cancelling"
                    else (
                        "completed"
                        if code == 0
                        and result.is_file()
                        and size <= 2 * 1024 * 1024
                        and not state.get("error")
                        else "failed"
                    )
                )
                self.store.update(
                    tid,
                    status=status,
                    exit_code=code,
                    finished_at=now(),
                    stage={
                        "completed": "已完成",
                        "cancelled": "已取消",
                        "failed": "执行失败",
                    }[status],
                    error=state.get("error")
                    or (
                        None
                        if status in ("completed", "cancelled")
                        else "执行未完成；查看日志与保留的诊断结果"
                    ),
                )
            except Exception as exc:
                self.kill(task, process)
                self.store.update(
                    tid, status="failed", error=type(exc).__name__, finished_at=now()
                )
            finally:
                timer.cancel()
                process.stdout.close()
                with self.lock:
                    self.current = None
                self.store.event(tid, "任务结束：" + self.store.task(tid)["status"])

    def timeout(self, tid, process):
        if process.poll() is None:
            self.store.update(tid, error="任务超时")
            self.kill(self.store.task(tid), process)

    def close(self):
        self.closed = True
        if self.current:
            self.cancel(self.current[0])
        self.queue.put(None)
        self.thread.join(timeout=25)
