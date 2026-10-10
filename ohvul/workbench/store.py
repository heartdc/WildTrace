from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / "workbench.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, body TEXT);
                CREATE TABLE IF NOT EXISTS reviews (seq INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT, body TEXT);
                CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT);
                CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS case_versions (case_id TEXT, revision INTEGER, body TEXT NOT NULL,
                    PRIMARY KEY(case_id, revision));
            """)
        for task in self.tasks():
            if task["status"] in ("queued", "running", "cancelling"):
                self.update(
                    task["id"],
                    status="interrupted",
                    finished_at=now(),
                    error="服务已重启；任务未自动重跑",
                )

    def tasks(self):
        with self.lock:
            return [
                json.loads(r[0])
                for r in self.db.execute("SELECT body FROM tasks ORDER BY rowid DESC")
            ]

    def task(self, tid):
        with self.lock:
            row = self.db.execute(
                "SELECT body FROM tasks WHERE id=?", (tid,)
            ).fetchone()
        if row is None:
            raise ValueError("Task not found")
        return json.loads(row[0])

    def put(self, task):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO tasks VALUES (?,?)",
                (task["id"], json.dumps(task, ensure_ascii=False)),
            )

    def update(self, tid, **changes):
        with self.lock, self.db:
            task = self.task(tid)
            task.update(changes)
            self.db.execute(
                "UPDATE tasks SET body=? WHERE id=?",
                (json.dumps(task, ensure_ascii=False), tid),
            )
        return task

    def event(self, tid, text):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO events(task_id,body) VALUES (?,?)",
                (
                    tid,
                    json.dumps(
                        {"time": now(), "text": text[:8000]}, ensure_ascii=False
                    ),
                ),
            )

    def events(self, tid, after=0):
        with self.lock:
            rows = self.db.execute(
                "SELECT seq,body FROM events WHERE task_id=? AND seq>? ORDER BY seq LIMIT 200",
                (tid, after),
            ).fetchall()
        return [{"id": r[0], **json.loads(r[1])} for r in rows]

    def review(self, item, body):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO reviews(item,body) VALUES (?,?)",
                (item, json.dumps({**body, "time": now()}, ensure_ascii=False)),
            )

    def reviews(self, item):
        with self.lock:
            return [
                json.loads(r[0])
                for r in self.db.execute(
                    "SELECT body FROM reviews WHERE item=? ORDER BY seq", (item,)
                )
            ]

    def settings(self, default):
        with self.lock:
            row = self.db.execute("SELECT body FROM settings WHERE id=1").fetchone()
        return json.loads(row[0]) if row else default

    def save_settings(self, value):
        with self.lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO settings VALUES (1,?)", (json.dumps(value),)
            )

    def projects(self):
        with self.lock:
            return [
                json.loads(r[0])
                for r in self.db.execute("SELECT body FROM projects ORDER BY rowid")
            ]

    def project(self, pid):
        with self.lock:
            row = self.db.execute(
                "SELECT body FROM projects WHERE id=?", (pid,)
            ).fetchone()
        if row is None:
            raise ValueError("源码项目不存在")
        return json.loads(row[0])

    def save_project(self, value):
        with self.lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO projects VALUES (?,?)",
                (value["id"], json.dumps(value, ensure_ascii=False)),
            )

    def case_ids(self):
        with self.lock:
            return [
                r[0]
                for r in self.db.execute(
                    "SELECT DISTINCT case_id FROM case_versions ORDER BY case_id"
                )
            ]

    def case_versions(self, cid):
        with self.lock:
            return [
                json.loads(r[0])
                for r in self.db.execute(
                    "SELECT body FROM case_versions WHERE case_id=? ORDER BY revision",
                    (cid,),
                )
            ]

    def append_case(self, cid, expected_revision, body, author, note):
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT MAX(revision) FROM case_versions WHERE case_id=?", (cid,)
            ).fetchone()
            current = row[0] or 0
            if current != expected_revision:
                raise ValueError("案例已被更新；请刷新后再保存，当前修改尚未覆盖")
            value = {
                "revision": current + 1,
                "time": now(),
                "author": author,
                "note": note,
                **body,
            }
            self.db.execute(
                "INSERT INTO case_versions VALUES (?,?,?)",
                (cid, current + 1, json.dumps(value, ensure_ascii=False)),
            )
            return value
