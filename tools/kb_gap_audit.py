"""Audit an OpenHarmony third_party component for upstream fix gaps.

Given a component git repo (full history), the raw cvelistV5 tree and the
upstream product name, this tool reproduces the four-signal gap audit used
for the curl cases as a reusable pipeline:

  L1  cve-grep    the component repo mentions the CVE id in any commit
                  message -> explicit backport exists
  L2  time window the CVE became public after the repo's baseline snapshot
                  (README.OpenSource last-change commit) -> the vendored
                  code predates disclosure and cannot carry the fix
  L3  versions    the vendored baseline version falls inside the record's
                  affected version ranges
  L4  source      (manual follow-up) the fix's code signature is absent
                  from the vendored tree

The tool automates L1-L3 and emits gap_candidate leads for L4. Candidates
are review leads only — never a vulnerability verdict.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

_PRODUCT_HINT_MIN_LEN = 3
_N_PREFIX = re.compile(r"^[nN](?=\d)")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def baseline_manifest(repo: Path):
    """(name, version, snapshot_date) from HEAD's README.OpenSource.

    snapshot_date proxies the vendored baseline import time as the last
    commit that touched README.OpenSource (version bumps ride along)."""
    try:
        raw = _git(repo, "show", "HEAD:README.OpenSource")
    except RuntimeError:
        return None, None, None
    entries = json.loads(re.sub(r",(\s*[}\]])", r"\1", raw.lstrip())) \
        if raw.lstrip().startswith("[") else []
    name = version = None
    for entry in entries:
        if isinstance(entry, dict):
            v = entry.get("Version Number") or entry.get("Version")
            if isinstance(v, str) and v.strip():
                n = entry.get("Name")
                name = n.strip() if isinstance(n, str) else None
                version = v.strip()
                break
    stamp = _git(repo, "log", "-1", "--format=%cI", "--", "README.OpenSource").strip()
    snapshot = stamp[:10] if stamp else None
    return name, version, snapshot


def _version_key(text: str):
    """Numeric segments for a fuzzy comparison; None when unparseable.

    Strips the ffmpeg 'n' prefix and leading 'v'; non-numeric tails are
    dropped, so '7.1.1~backend' compares as 7.1.1 (documented approximation)."""
    cleaned = _N_PREFIX.sub("", (text or "").strip().lstrip("vV"))
    segs = re.findall(r"\d+", cleaned)
    if not segs:
        return None
    return [int(s) for s in segs]


def _key_in_range(low_key, high_key, key, *, high_inclusive=False) -> bool:
    def pad(a, b):
        n = max(len(a), len(b))
        return a + [0] * (n - len(a)), b + [0] * (n - len(b))
    if low_key is not None:
        lhs, rhs = pad(low_key, key)
        if lhs > rhs:
            return False
    if high_key is not None:
        lhs, rhs = pad(key, high_key)
        if lhs > rhs or (lhs == rhs and not high_inclusive):
            return False
    return True


def baseline_in_affected(baseline: str, affected: list) -> str:
    """'covered' / 'outside' / 'unknown' for one cna.affected[] block."""
    base_key = _version_key(baseline)
    if base_key is None:
        return "unknown"
    for block in affected:
        for entry in block.get("versions", []):
            if entry.get("status") != "affected":
                continue
            low = entry.get("version") or "0"
            if low in ("0", "unspecified", "n/a"):
                low_key = None
            else:
                low_key = _version_key(low)
            less_than_or_equal = entry.get("lessThanOrEqual")
            high = entry.get("lessThan") or less_than_or_equal
            high_key = _version_key(high) if high else None
            if _key_in_range(low_key, high_key, base_key,
                             high_inclusive=bool(less_than_or_equal and not entry.get("lessThan"))):
                return "covered"
    return "outside"


def collect_product_cves(cvelist_root: Path, product: str, since_year: int):
    """Yield normalized records whose cna affected product matches."""
    needle = product.lower()
    for year_dir in sorted(p for p in cvelist_root.iterdir() if p.is_dir()):
        try:
            year = int(year_dir.name)
        except ValueError:
            continue
        if year < since_year:
            continue
        for path in sorted(year_dir.rglob("CVE-*.json")):
            try:
                doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (ValueError, OSError):
                continue
            cna = (doc.get("containers", {}).get("cna") or {})
            affected = cna.get("affected") or []
            if not any((b.get("product") or "").lower() == needle for b in affected):
                continue
            meta = doc.get("cveMetadata") or {}
            published = cna.get("datePublic") or meta.get("datePublished") \
                or meta.get("dateUpdated")
            refs = [r.get("url") for r in cna.get("references", [])
                    if isinstance(r, dict) and r.get("url")]
            yield {
                "id": meta.get("cveId") or path.stem,
                "published": (published or "")[:10] or None,
                "cwes": sorted({s.get("cweId") for s in cna.get("problemTypes", [])
                                for s in s.get("descriptions", [])
                                if s.get("cweId")}),
                "summary": next((d.get("value") for d in cna.get("descriptions", [])
                                 if d.get("lang") == "en"), "")[:300],
                "coverage": None,  # filled by caller
                "affected_raw": affected,
                "refs": refs[:4],
            }


def cve_grep(repo: Path, cve_id: str) -> list:
    """L1 backport evidence: commit messages AND repo-root patch files.

    Some OH component repos (e.g. third_party_libxml2) carry backports as
    in-tree *.patch files applied by BUILD.gn rather than commits; a
    filename match in the root tree counts as evidence (tracked patch
    files are applied by the build)."""
    out = _git(repo, "log", "--all", "-i", "--format=%h%x00%cI%x00%s",
               f"--grep={cve_id}")
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\x00", 2)
        rows.append({"sha": parts[0], "date": parts[1][:10],
                     "subject": parts[2][:160] if len(parts) > 2 else ""})
    tree = _git(repo, "ls-tree", "--name-only", "HEAD")
    suffix = cve_id.split("-")[-1]
    for name in tree.splitlines():
        base = name.strip()
        if base.endswith(".patch") and (cve_id.lower() in base.lower()
                                        or "-" + suffix + "-" in base):
            rows.append({"sha": "patch-file", "date": "",
                         "subject": base[:160]})
    return rows


def audit(repo: Path, cvelist_root: Path, product: str, since_year: int) -> dict:
    name, version, snapshot = baseline_manifest(repo)
    if not version or not snapshot:
        raise RuntimeError("README.OpenSource baseline not readable; not an OH component repo?")
    report = {
        "schema": "kb-gap-audit-0.1",
        "repo": str(repo), "product": product,
        "baseline": {"name": name, "version": version, "snapshot_date": snapshot},
        "candidates_only": True,
        "records": [],
    }
    counts = {"backported": 0, "gap_candidate": 0, "predates_snapshot": 0,
              "outside_baseline": 0, "unknown": 0}
    for rec in collect_product_cves(cvelist_root, product, since_year):
        rec["coverage"] = baseline_in_affected(version, rec.pop("affected_raw"))
        hits = cve_grep(repo, rec["id"])
        rec["oh_commits"] = hits[:5]
        if hits:
            status = "backported"
        elif rec["coverage"] == "outside":
            status = "outside_baseline"
        elif rec["coverage"] == "unknown":
            status = "unknown"
        elif not rec["published"]:
            status = "unknown"
        elif rec["published"] >= snapshot:
            status = "gap_candidate"
        else:
            status = "predates_snapshot"
        rec["status"] = status
        counts[status] += 1
        report["records"].append(rec)
    report["counts"] = counts
    report["records"].sort(key=lambda r: (r["status"] != "gap_candidate",
                                          r["published"] or "", r["id"]))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True,
                        help="OpenHarmony component git repo (full history)")
    parser.add_argument("--cvelist", type=Path, required=True,
                        help="cvelistV5 tree root (contains year directories)")
    parser.add_argument("--product", required=True,
                        help="upstream product name to match in cna.affected")
    parser.add_argument("--since-year", type=int, default=None,
                        help="first CVE year to scan (default: snapshot year - 1)")
    parser.add_argument("--out", type=Path, default=None,
                        help="output json path (default: gap_audit_<product>.json)")
    args = parser.parse_args()

    _, _, snapshot = baseline_manifest(args.repo)
    since = args.since_year or (int(snapshot[:4]) - 1 if snapshot else 2015)
    report = audit(args.repo, args.cvelist, args.product, since)
    out = args.out or Path(f"gap_audit_{args.product}.json")
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    base = report["baseline"]
    print(f"baseline {base['name']} {base['version']} @ {base['snapshot_date']}; "
          f"scanned CVEs >= {since}")
    for status, n in report["counts"].items():
        print(f"  {status:18} {n}")
    gaps = [r for r in report["records"] if r["status"] == "gap_candidate"]
    for r in gaps[:15]:
        print(f"  GAP {r['id']} pub={r['published']} {r['summary'][:90]}")
    if len(gaps) > 15:
        print(f"  ... and {len(gaps) - 15} more")
    print(f"wrote {out} — candidates need the manual L4 source-signature check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
