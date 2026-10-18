"""Seeded recall benchmark: synththesize a component with known-form defects
(positive seeds) and guarded look-alikes (negative seeds), run the scanner
layers, and measure recall / false-positive specificity.

Positive seeds model real OH idioms (sptr<>/GetRemoteProxy, CHECK_AND_RETURN,
SoftBusFree, CJ {head,size} arrays). A detection matches a seed when the
pattern family equals the expected one and the reported line is within
LINE_WINDOW of the seeded line. The report is a measurement, not a claim:
false negatives are listed with their seeded line for inspection.
"""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul.autopilot import (  # noqa: E402
    scan_p1, scan_p4, scan_p5, scan_p6, scan_p7, scan_p8,
)

LINE_WINDOW = 6

# (seed_id, expected_pattern, file, source) — the line number of the anchor
# comment 'SEED:<id>' is the expected detection site.
POSITIVE = [
    ("S01_gt1_local_sptr", "P6_null_deref", "gt1.cpp", """
#include "iremote_stub.h"
class IWidget { public: virtual int Ping() = 0; };
sptr<IWidget> GetWidget();
int UseWidget() {
    sptr<IWidget> proxy = GetWidget();   // SEED:S01_gt1_local_sptr
    return proxy->Ping();                // deref without null check
}
"""),
    ("S02_gt2_member_ptr", "P6_null_deref", "gt2.cpp", """
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
    ("S03_gt3_macro_ptr", "P6_null_deref", "gt3.cpp", """
#define OBTAIN(dst, src) (dst) = (src)
static int* FetchRaw();
int Consume() {
    int* p = nullptr;
    OBTAIN(p, FetchRaw());
    return *p;                           // SEED:S03_gt3_macro_ptr
}
"""),
    ("S04_param_null_deref", "P6_null_deref", "p6a.c", """
struct Node { int a; };
void ConsumeNodes(struct Node* head, int size) {
    int total = 0;
    for (int i = 0; i < size; i++) {
        total += head[i].a;              // SEED:S04_param_null_deref
    }
    (void)total;
}
"""),
    ("S05_assigned_null_deref", "P6_null_deref", "p6b.c", """
struct Buf { int len; };
static struct Buf* Find(int id) { (void)id; return 0; }
int Use(int id) {
    struct Buf* b = NULL;
    b = Find(id);
    return b->len;                       // SEED:S05_assigned_null_deref
}
"""),
    ("S06_plain_uaf", "P8_use_after_free", "p8a.c", """
#include <stdlib.h>
void Process(int* data) {
    free(data);
    data[0] = 1;                         // SEED:S06_plain_uaf
}
"""),
    ("S07_fallthrough_uaf", "P8_use_after_free", "p8b.c", """
#include <stdlib.h>
int Process(int err, int* p) {
    if (err) { free(p); }                // no return: falls through to use
    p[0] = 1;                            // SEED:S07_fallthrough_uaf
    return 0;
}
"""),
    ("S08_alloc_overflow", "P7_alloc_overflow", "p7.c", """
#include <stdlib.h>
struct Row { char cell[64]; };
struct Row* Alloc(int n) {
    return (struct Row*)malloc(sizeof(struct Row) * n);  // SEED:S08_alloc_overflow
}
"""),
    ("S09_unbounded_copy", "P4_unbounded_copy", "p4.c", """
#include <string.h>
void CopyData(char* dst, const char* src, int len) {
    memcpy(dst, src, len);               // SEED:S09_unbounded_copy
}
"""),
    ("S10_stack_overflow", "P5_stack_overflow", "p5.c", """
#include <string.h>
void HandleName(const char* name) {
    char buf[32];
    strcpy(buf, name);                   // SEED:S10_stack_overflow
}
"""),
    ("S11_cj_null_len", "P1_null_len", "frameworks/cj/src/cj_seed.cpp", """
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

# Look-alikes that must NOT fire (guarded / suppressed forms).
NEGATIVE = [
    ("N01_guarded_param", "p6a.c", """
struct Node { int a; };
void SafeConsume(struct Node* head, int size) {
    if (head == NULL || size <= 0) {     // guard present
        return;
    }
    int total = 0;
    for (int i = 0; i < size; i++) {
        total += head[i].a;
    }
    (void)total;
}
"""),
    ("N02_free_then_null", "p8a.c", """
#include <stdlib.h>
void SafeFree(int* p) {
    free(p);
    p = NULL;
}
"""),
    ("N03_escape_branch_free", "p8b.c", """
#include <stdlib.h>
int SafePath(int err, int* p) {
    if (err != 0) { free(p); return -1; }   // escape-terminated: not a UAF
    p[0] = 1;
    return 0;
}
"""),
    ("N04_alloc_with_guard", "p7.c", """
#include <stdlib.h>
struct Row { char cell[64]; };
struct Row* SafeAlloc(int n) {
    if (n <= 0 || (size_t)n > SIZE_MAX / sizeof(struct Row)) return NULL;
    return (struct Row*)malloc(sizeof(struct Row) * n);
}
"""),
    ("N05_gt1_checked", "gt1.cpp", """
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
        existing = p.read_text() if p.exists() else ""
        p.write_text(existing + src, encoding="utf-8")
        metas.append({"id": seed_id, "pattern": pattern, "file": rel,
                      "line": seed_line(src, seed_id)})
    for seed_id, rel, src in NEGATIVE:
        p = root / rel
        existing = p.read_text() if p.exists() else ""
        p.write_text(existing + src, encoding="utf-8")
    return metas


def run_benchmark(root: Path):
    metas = build(root)
    findings = []
    for scan in (scan_p1, scan_p4, scan_p5, scan_p6, scan_p7, scan_p8):
        findings += list(scan(root))
    hits, misses = [], []
    for m in metas:
        hit = None
        for f in findings:
            rel = str(f.file).replace("\\", "/")
            if (f.pattern == m["pattern"] and rel.endswith(m["file"])
                    and abs(int(f.line) - m["line"]) <= LINE_WINDOW):
                hit = f
                break
        (hits if hit else misses).append({**m, "matched": bool(hit)})
    fp = []
    hit_sites = {(m["file"], m["line"]) for m in metas}
    for f in findings:
        rel = str(f.file).replace("\\", "/")
        near_seed = any(rel.endswith(h[0]) and abs(int(f.line) - h[1]) <= LINE_WINDOW
                        for h in hit_sites)
        if not near_seed:
            fp.append({"pattern": f.pattern, "file": rel, "line": int(f.line)})
    return {
        "schema": "seed-recall-benchmark-0.1",
        "positive_seeds": len(metas), "detected": len(hits),
        "recall": round(len(hits) / len(metas), 3) if metas else None,
        "false_negatives": misses,
        "negative_seeds": len(NEGATIVE),
        "off_seed_findings": fp,
        "off_seed_count": len(fp),
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
          f"off_seed={report['off_seed_count']}/{report['negative_seeds']} negatives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
