"""Serializable evidence records; hashes detect changes, not authenticity."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class EvidenceBundle:
    evidence_id: str
    stage: str
    source: dict[str, Any]
    environment: dict[str, Any]
    inputs: list[dict[str, str]] = field(default_factory=list)
    artifacts: list[dict[str, str]] = field(default_factory=list)
    verdict: str = "candidate"
    parent_id: str | None = None
    bundle_version: str = "1"

    def to_dict(self) -> dict:
        return asdict(self)


def make_bundle(stage: str, source: dict[str, Any], *,
                evidence: dict[str, Any] | None = None,
                verdict: str = "candidate") -> EvidenceBundle:
    artifacts = [{"name": key, "sha256": digest(value)}
                 for key, value in sorted((evidence or {}).items())]
    bundle = EvidenceBundle("", stage, source,
                            {"execution": "none", "network": "disabled"},
                            artifacts=artifacts, verdict=verdict)
    payload = bundle.to_dict()
    payload.pop("evidence_id")
    return EvidenceBundle(evidence_id="EB-" + digest(payload), **payload)


def validate_bundle(bundle: dict) -> None:
    if not isinstance(bundle, dict) or bundle.get("bundle_version") != "1":
        raise ValueError("Unsupported evidence bundle; regenerate legacy results")
    payload = dict(bundle)
    evidence_id = payload.pop("evidence_id", None)
    if evidence_id != "EB-" + digest(payload):
        raise ValueError("Evidence checksum mismatch")
    if not isinstance(payload.get("source"), dict) or not isinstance(payload.get("artifacts"), list):
        raise ValueError("Invalid evidence structure")
