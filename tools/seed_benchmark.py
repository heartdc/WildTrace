"""Seeded recall benchmark: synthesize a component with known-form defects
(positive seeds) and guarded look-alikes (negative seeds), run the scanner
layers, and measure recall / false-positive specificity.

v2 (external review F01): every seed lives in its OWN file — a finding in a
negative file can never be attributed to a positive seed, and positive
matching is by (pattern family, exact file) with a line window only inside
that seed's own file. Off-family findings at positive sites are reported as
misattributions and never count toward recall. Findings in negative files
are false positives, whatever the family.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.autopilot import (  # noqa: E402
    scan_p1, scan_p4, scan_p5, scan_p6, scan_p7, scan_p8,
)

LINE_WINDOW = 8

# (seed_id, expected_pattern, file, source). The anchor comment
# 'SEED:<id>' marks the expected detection site; one seed per file.
POSITIVE = [
    ("S01_gt1_local_sptr", "P6_null_deref", "seed_s01.cpp", """
#include "iremote_stub.h"
class IWidget { public: virtual int Ping() = 0; };
sptr<IWidget> GetWidget();
int UseWidget() {
    sptr<IWidget> proxy = GetWidget();   // SEED:S01_gt1_local_sptr
    return proxy->Ping();
}
"""),
    ("S02_gt2_member_ptr", "P6_null_deref", "seed_s02.cpp", """
struct Impl { int Run(); };
class Service {
public:
    Service() : pimpl(nullptr) {}
    int Start() {
        return pimpl->Run();             // SEED:S02_gt2_member_ptr
    }
private:
    Impl* pimpl;
};
"""),
    ("S03_gt3_bare_deref", "P6_null_deref", "seed_s03.cpp", """
static int* FetchRaw();
int Consume() {
    int* p = nullptr;
    p = FetchRaw();
    return *p;                           // SEED:S03_gt3_bare_deref
}
"""),
    ("S04_param_null_deref", "P6_null_deref", "seed_s04.c", """
struct Node { int a; };
void ConsumeNodes(struct Node* head, int size) {
    int total = 0;
    for (int i = 0; i < size; i++) {
        total += head[i].a;              // SEED:S04_param_null_deref
    }
    (void)total;
}
"""),
    ("S05_assigned_null_deref", "P6_null_deref", "seed_s05.c", """
struct Buf { int len; };
static struct Buf* Find(int id) { (void)id; return 0; }
int Use(int id) {
    struct Buf* b = NULL;
    b = Find(id);
    return b->len;                       // SEED:S05_assigned_null_deref
}
"""),
    ("S06_plain_uaf", "P8_use_after_free", "seed_s06.c", """
#include <stdlib.h>
void Process(int* data) {
    free(data);
    data[0] = 1;                         // SEED:S06_plain_uaf
}
"""),
    ("S07_fallthrough_uaf", "P8_use_after_free", "seed_s07.c", """
#include <stdlib.h>
int Process(int err, int* p) {
    if (err) { free(p); }
    p[0] = 1;                            // SEED:S07_fallthrough_uaf
    return 0;
}
"""),
    ("S08_alloc_overflow", "P7_alloc_overflow", "seed_s08.c", """
#include <stdlib.h>
struct Row { char cell[64]; };
struct Row* Alloc(int n) {
    return (struct Row*)malloc(sizeof(struct Row) * n);  // SEED:S08_alloc_overflow
}
"""),
    ("S09_unbounded_copy", "P4_unbounded_copy", "seed_s09.c", """
#include <string.h>
void CopyData(char* dst, const char* src, int len) {
    memcpy(dst, src, len);               // SEED:S09_unbounded_copy
}
"""),
    ("S10_stack_overflow", "P5_stack_overflow", "seed_s10.c", """
#include <string.h>
void HandleName(const char* name) {
    char buf[32];
    strcpy(buf, name);                   // SEED:S10_stack_overflow
}
"""),
    ("S11_cj_null_len", "P1_null_len", "frameworks/cj/src/seed_s11.cpp", """
typedef struct { char* key; void* value; } CRow;
typedef struct { CRow* head; int64_t size; } CArrStr;
void ProcessRows(CArrStr rows) {
    for (int64_t i = 0; i < rows.size; i++) {
        if (rows.head[i].key == 0) continue;
        Handle(rows.head[i].key);        // SEED:S11_cj_null_len
    }
}
void Handle(char* k);
"""),
]

# Look-alikes in their own files. `silent_for` lists the pattern families
# the seed MUST be silent for (a violation is a real false positive);
# P6 is a candidate GENERATOR — it fires on every unguarded param deref by
# design (the funnel ranks later), so seeds about other layers' suppression
# logic only hold P6 silent when the deref is actually null-guarded.
NEGATIVE = [
    ("N01_guarded_param", "neg_n01.c", "all", """
struct Node { int a; };
void SafeConsume(struct Node* head, int size) {
    if (head == NULL || size <= 0) {
        return;
    }
    int total = 0;
    for (int i = 0; i < size; i++) {
        total += head[i].a;
    }
    (void)total;
}
"""),
    ("N02_free_then_null", "neg_n02.c", "all", """
#include <stdlib.h>
void SafeFree(int* p) {
    free(p);
    p = NULL;
}
"""),
    ("N03_escape_branch_free", "neg_n03.c", ["P8_use_after_free"], """
#include <stdlib.h>
int SafePath(int err, int* p) {
    if (err != 0) { free(p); return -1; }
    p[0] = 1;
    return 0;
}
"""),
    ("N04_alloc_with_guard", "neg_n04.c", "all", """
#include <stdlib.h>
#include <stdint.h>
struct Row { char cell[64]; };
struct Row* SafeAlloc(int n) {
    if (n <= 0 || (size_t)n > SIZE_MAX / sizeof(struct Row)) return NULL;
    return (struct Row*)malloc(sizeof(struct Row) * n);
}
"""),
    ("N05_gt1_checked", "neg_n05.cpp", "all", """
#include "iremote_stub.h"
class IWidget2 { public: virtual int Ping() = 0; };
sptr<IWidget2> GetWidget2();
int UseWidgetChecked() {
    sptr<IWidget2> proxy = GetWidget2();
    if (proxy == nullptr) {
        return -1;
    }
    return proxy->Ping();
}
"""),
]


def seed_line(source: str, seed_id: str) -> int:
    for i, line in enumerate(source.splitlines(), 1):
        if f"SEED:{seed_id}" in line:
            return i
    raise ValueError(f"seed anchor missing: {seed_id}")


def build(root: Path):
    metas = []
    for seed_id, pattern, rel, src in POSITIVE:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
        metas.append({"id": seed_id, "pattern": pattern, "file": rel,
                      "line": seed_line(src, seed_id)})
    for seed_id, rel, silent_for, src in NEGATIVE:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return metas


def _rel(f_file, root):
    return str(f_file).replace("\\", "/").removeprefix(str(root).replace("\\", "/") + "/")


def run_benchmark(root: Path):
    metas = build(root)
    findings = []
    for scan in (scan_p1, scan_p4, scan_p5, scan_p6, scan_p7, scan_p8):
        findings += list(scan(root))

    hits, misses, misattributed = [], [], []
    for m in metas:
        right_family = [f for f in findings
                        if f.pattern == m["pattern"]
                        and _rel(f.file, root).endswith(m["file"])
                        and abs(int(f.line) - m["line"]) <= LINE_WINDOW]
        wrong_family = [f for f in findings
                        if f.pattern != m["pattern"]
                        and _rel(f.file, root).endswith(m["file"])]
        if right_family:
            hits.append({**m, "matched": True})
        else:
            misses.append({**m, "matched": False})
        for f in wrong_family:
            misattributed.append({"seed": m["id"], "got_pattern": f.pattern,
                                  "line": int(f.line)})

    neg_spec = {rel: silent_for for _, rel, silent_for, _ in NEGATIVE}
    neg_files = set(neg_spec)
    violations, by_design = [], []
    for f in findings:
        rel = _rel(f.file, root)
        if rel not in neg_files:
            continue
        silent_for = neg_spec[rel]
        if silent_for == "all" or f.pattern in silent_for:
            violations.append({"pattern": f.pattern, "file": rel,
                               "line": int(f.line)})
        else:
            # e.g. P6 candidate generation on an unguarded param in a seed
            # written to test another layer's suppression — informational
            by_design.append({"pattern": f.pattern, "file": rel,
                              "line": int(f.line)})
    stray = [
        {"pattern": f.pattern, "file": _rel(f.file, root), "line": int(f.line)}
        for f in findings
        if _rel(f.file, root) not in neg_files
        and not any(_rel(f.file, root).endswith(m["file"]) for m in metas)]

    return {
        "schema": "seed-recall-benchmark-0.2",
        "attribution": "per-seed files; positive match = family+file+window; "
                       "negative violations per silent_for declaration",
        "positive_seeds": len(metas), "detected": len(hits),
        "recall": round(len(hits) / len(metas), 3) if metas else None,
        "false_negatives": misses,
        "misattributed_at_positive_sites": misattributed,
        "negative_seeds": len(NEGATIVE),
        "violations": violations,
        "by_design_candidate_firings": by_design,
        "stray_findings_outside_corpus": stray,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="wt_seed_") as tmp:
        report = run_benchmark(Path(tmp))
    text = json.dumps(report, ensure_ascii=False, indent=1)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(f"RECALL={report['recall']} ({report['detected']}/{report['positive_seeds']}) "
          f"violations={len(report["violations"])} "
          f"misattributed={len(report['misattributed_at_positive_sites'])} "
          f"stray={len(report['stray_findings_outside_corpus'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
