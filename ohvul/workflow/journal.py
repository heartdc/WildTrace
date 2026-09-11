"""Append-only local audit events. A commit marker alone is not proof."""
from pathlib import Path
import json
import os
from datetime import datetime, timezone

EVENTS = {"begin", "result", "checkpoint", "review_batch", "commit", "abort"}


def latest_attempt(records, task_id):
    records = [record for record in records if record["task_id"] == task_id]
    starts = [i for i, record in enumerate(records) if record["event"] == "begin"]
    return records[starts[-1]:] if starts else records


def attempt_status(records):
    events = [record["event"] for record in records]
    if not events:
        return "absent"
    order = ["begin", "result", "checkpoint", "commit"]
    if events == order:
        return "committed"
    if events[-1] == "abort" and events[:-1] in [order[:i] for i in range(1, 4)]:
        return "aborted"
    if events in [order[:i] for i in range(1, 4)]:
        return "incomplete"
    return "invalid"


class AuditJournal:
    def __init__(self, path: Path):
        self.path = path

    def append(self, event: str, task_id: str, **data):
        if event not in EVENTS or not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("invalid journal event or task id")
        record = {"event": event, "task_id": task_id, "created_at": datetime.now(timezone.utc).isoformat(), **data}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("journal path must not be a symbolic link")
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def append_review_batch(self, batch):
        if not isinstance(batch, dict) or batch.get("batch_schema") != "0.1":
            raise ValueError("invalid review batch")
        task_id = batch.get("task_id")
        if not isinstance(task_id, str) or not task_id or batch.get("final_vulnerability_verdict") is not False:
            raise ValueError("review batch task id or verdict invalid")
        self.append("review_batch", task_id, batch_id=batch.get("batch_id"), report_sha256=batch.get("report_sha256"), final_vulnerability_verdict=batch.get("final_vulnerability_verdict"))

    def read(self):
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or value.get("event") not in EVENTS:
                raise ValueError("invalid journal record")
            if not isinstance(value.get("task_id"), str) or not value["task_id"].strip():
                raise ValueError("invalid journal task id")
            records.append(value)
        return records

    def last_status(self, task_id):
        return attempt_status(latest_attempt(self.read(), task_id))


def validate_commit(journal, task_id, result_path, checkpoint_path):
    records = latest_attempt(journal.read(), task_id)
    if attempt_status(records) != "committed":
        raise ValueError("journal has no valid committed sequence")
    from .fsm import load_checkpoint, validate_checkpoint_result
    checkpoint = load_checkpoint(checkpoint_path)
    if checkpoint.task_id != task_id:
        raise ValueError("checkpoint task differs from journal")
    validate_checkpoint_result(checkpoint, result_path)
    if records[1].get("result_sha256") != checkpoint.result_sha256:
        raise ValueError("journal result digest differs from checkpoint")
    if records[2].get("state") != checkpoint.state:
        raise ValueError("journal state differs from checkpoint")
    if records[0].get("source_snapshot_sha256") != checkpoint.source_snapshot_sha256:
        raise ValueError("journal source snapshot differs from checkpoint")



