"""Offline validation of saved audit result evidence and references."""
import argparse
import json
from pathlib import Path
from .domain.evidence import digest, validate_bundle


def validate_result(result: dict) -> int:
    if not isinstance(result, dict) or result.get("schema_version") != "0.3":
        raise ValueError("Expected audit schema 0.3; regenerate legacy results")
    indexed = {}
    for bundle in result["evidence_bundles"]:
        validate_bundle(bundle)
        key = bundle["evidence_id"]
        if key in indexed and indexed[key] != bundle:
            raise ValueError("Conflicting evidence identifier")
        indexed[key] = bundle
    observations = result.get('rule_observations', [])
    if not isinstance(observations, list):
        raise ValueError('Invalid rule observations')
    for observation in observations:
        if (not isinstance(observation, dict) or observation.get('status') != 'observation'
                or not isinstance(observation.get('evidence'), dict)
                or observation['evidence'].get('final_verdict') != 'undetermined'):
            raise ValueError('Rule observation cannot make a vulnerability verdict')
    for finding in result["findings"] + observations:
        bundle = indexed.get(finding.get("evidence_id"))
        if bundle is None:
            raise ValueError("Missing finding evidence")
        hashes = {item["name"]: item["sha256"] for item in bundle["artifacts"]}
        for name, value in finding["evidence"].items():
            if hashes.get(name) != digest(value):
                raise ValueError("Finding evidence differs from bundle")
        if ('cwe_candidate' in finding['evidence'] and
                finding.get('cwe_candidate') != finding['evidence']['cwe_candidate']):
            raise ValueError('Finding CWE differs from bound evidence')
        location = finding["location"]
        if any(location[key] != bundle["source"].get(key) for key in ("file", "line")):
            raise ValueError("Finding location differs from bundle")
    for group in result.get("known_vulnerability_matches", []):
        for match in group["matches"] + group.get("unresolved", []):
            bundle = indexed.get(match.get("evidence_id"))
            if bundle is None:
                raise ValueError("Missing metadata evidence")
            hashes = {item["name"]: item["sha256"] for item in bundle["artifacts"]}
            if hashes.get("record_id") != digest(str(match.get("id", ""))):
                raise ValueError("Metadata identifier differs from bundle")
            if bundle["source"].get("metadata_source") != match.get("source"):
                raise ValueError("Metadata source differs from bundle")
            record_artifact = next((a for a in bundle["artifacts"] if a["name"] == "record"), None)
            if record_artifact is None:
                raise ValueError("Metadata record is not bound")
            # The bundle binds the complete source record; presentation fields must agree.
            expected = match.get("_metadata_record")
            if expected is not None:
                for field in ("id", "cwe", "summary"):
                    if match.get(field) != expected.get(field):
                        raise ValueError("Metadata presentation differs from source record")
    return len(indexed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()
    try:
        if args.checkpoint:
            from .workflow.fsm import load_checkpoint, validate_checkpoint_result
            validate_checkpoint_result(load_checkpoint(args.checkpoint), args.result)
        count = validate_result(json.loads(args.result.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"OK: {count} distinct evidence records; not a vulnerability verdict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
