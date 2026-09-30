from __future__ import annotations
from dataclasses import dataclass, asdict
import json
import hashlib
import re
import os
import tempfile
from pathlib import Path

STATES = ("intake", "static_scan", "local_verification", "triage", "report", "human_review", "blocked", "completed")
MAX_RETRIES = 3

TRANSITIONS = {
 "intake": {"static_scan", "blocked"},
 "static_scan": {"triage", "local_verification", "blocked"},
 "local_verification": {"triage", "blocked"},
 "triage": {"report", "blocked"},
 "report": {"human_review", "blocked"},
 "human_review": {"completed", "static_scan", "blocked"},
 "blocked": {"intake", "static_scan"},
 "completed": set(),
}

@dataclass
class WorkflowCheckpoint:
 task_id: str
 checkpoint_version: str = "1"
 state: str = "intake"
 retry_count: int = 0
 last_error: str | None = None
 result_sha256: str | None = None
 source_snapshot_sha256: str | None = None

 def to_dict(self): return asdict(self)

 def transition(self, target: str, *, reason: str | None = None, verification_files=None):
  validate_checkpoint_data(self.to_dict())
  if target not in STATES: raise ValueError(f"unknown workflow state: {target}")
  if target not in TRANSITIONS[self.state]: raise ValueError(f"illegal transition: {self.state} -> {target}")
  if reason is not None and not isinstance(reason, str): raise ValueError("invalid transition reason")
  if self.state == "blocked" and self.retry_count >= MAX_RETRIES:
   raise ValueError("retry budget exhausted")
  if self.state == "local_verification" and target == "triage":
   if not isinstance(verification_files, (tuple, list)) or len(verification_files) != 3:
    raise ValueError("verified checkpoint/result/harness files required")
   from ohvul.verification_link import load_verified_checkpoint
   verified = load_verified_checkpoint(*verification_files)
   if verified.to_dict() != self.to_dict():
    raise ValueError("verified checkpoint differs from current workflow")
  if target == "blocked":
   self.last_error = reason or "unspecified_block"
  elif self.state == "blocked":
   self.retry_count += 1
   self.result_sha256 = None
   self.last_error = None
  self.state = target
  return self

def save_checkpoint(checkpoint: WorkflowCheckpoint, path: Path, *, force=False):
 validate_checkpoint_data(checkpoint.to_dict())
 if path.is_symlink(): raise ValueError("checkpoint path must not be a symbolic link")
 if path.exists() and not force: raise FileExistsError(f"checkpoint exists: {path}")
 path.parent.mkdir(parents=True, exist_ok=True)
 payload=(json.dumps(checkpoint.to_dict(), ensure_ascii=False, indent=2) + "\n").encode("utf-8")
 fd, temporary=tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
 try:
  with os.fdopen(fd, "wb") as stream:
   stream.write(payload); stream.flush(); os.fsync(stream.fileno())
  os.replace(temporary, path)
 except Exception:
  try: os.unlink(temporary)
  except OSError: pass
  raise

def load_checkpoint(path: Path) -> WorkflowCheckpoint:
 data=json.loads(path.read_text(encoding="utf-8-sig"))
 return validate_checkpoint_data(data)

def validate_checkpoint_data(data: dict) -> WorkflowCheckpoint:
 """Validate already-decoded checkpoint data without reopening a file."""
 if not isinstance(data, dict) or data.get("state") not in STATES or not isinstance(data.get("task_id"), str):
  raise ValueError("invalid workflow checkpoint")
 required={"checkpoint_version","task_id","state","retry_count","last_error","result_sha256","source_snapshot_sha256"}
 if set(data) != required: raise ValueError("invalid checkpoint fields")
 if data["checkpoint_version"] != "1" or not isinstance(data["task_id"],str) or not data["task_id"]: raise ValueError("invalid checkpoint version or task id")
 if type(data["retry_count"]) is not int or not 0 <= data["retry_count"] <= MAX_RETRIES: raise ValueError("invalid retry count")
 if data["last_error"] is not None and not isinstance(data["last_error"],str): raise ValueError("invalid last error")
 if data["result_sha256"] is not None and (not isinstance(data["result_sha256"],str) or not re.fullmatch(r"[0-9a-fA-F]{64}", data["result_sha256"])): raise ValueError("invalid result digest")
 if data["source_snapshot_sha256"] is not None and (not isinstance(data["source_snapshot_sha256"],str) or not re.fullmatch(r"[0-9a-fA-F]{64}", data["source_snapshot_sha256"])): raise ValueError("invalid source snapshot digest")
 return WorkflowCheckpoint(checkpoint_version="1", task_id=data["task_id"], state=data["state"], retry_count=data["retry_count"], last_error=data["last_error"], result_sha256=data["result_sha256"], source_snapshot_sha256=data["source_snapshot_sha256"])


def validate_checkpoint_result(checkpoint: WorkflowCheckpoint, result_path: Path) -> None:
 """Check an explicitly supplied result; never follow paths from checkpoints."""
 if checkpoint.state != "static_scan" or not checkpoint.result_sha256:
  raise ValueError("checkpoint has no completed scan result")
 raw = result_path.read_bytes()
 if hashlib.sha256(raw).hexdigest() != checkpoint.result_sha256:
  raise ValueError("result digest differs from checkpoint")
 result = json.loads(raw.decode("utf-8-sig"))
 workflow = result.get("workflow", {})
 if workflow.get("task_id") != checkpoint.task_id or workflow.get("state") != checkpoint.state:
  raise ValueError("result task or state differs from checkpoint")
 from ohvul.verify import validate_result
 validate_result(result)


def resume_blocked(checkpoint: WorkflowCheckpoint, target: str = "intake") -> WorkflowCheckpoint:
    """Explicit, bounded recovery; never resumes directly at report/completed."""
    if checkpoint.state != "blocked":
        raise ValueError("only blocked checkpoints can be resumed")
    if target not in ("intake", "static_scan"):
        raise ValueError("recovery target must be intake or static_scan")
    return checkpoint.transition(target)






