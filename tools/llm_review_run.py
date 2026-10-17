"""Drive ohvul.llm_review for a full queue with an explicit group list.

Avoids shell-quoting pitfalls (26 RG-ids on one command line) by calling
run_review directly. Modes:
  plan <model>            offline plan for every group in the ids file
  run  <model>            online run; key read from --key-file (single line)
  verify <model>          offline acceptance of a saved run directory

Usage:
  python tools/llm_review_run.py plan glm-5.3 \
      --summary .cache/comp_review/batch/summary-0004.json \
      --queue   .cache/comp_review/review/queue.json \
      --context .cache/comp_review/review/context.json \
      --root securec='D:\\stage\\bounds_checking_function' --root hilog_featured='D:\\stage' \
      --groups group_ids.txt --output .cache/llm_plan_glm53
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ohvul import llm_review  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "verify"))
    parser.add_argument("model")
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--root", action="append", default=[],
                        help="JOB=PATH source root, repeatable")
    parser.add_argument("--groups", type=Path, required=True,
                        help="file with one group id per line")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, default=None,
                        help="single-line API key file (run mode only)")
    args = parser.parse_args(argv)

    roots = {}
    for item in args.root:
        job, _, path = item.partition("=")
        if not job or not path:
            raise SystemExit(f"bad --root {item!r} (want JOB=PATH)")
        roots[job] = Path(path)
    ids = [x for x in args.groups.read_text(encoding="utf-8").split() if x]
    if not ids:
        raise SystemExit("group id file is empty")
    print(f"groups: {len(ids)} model: {args.model} mode: {args.mode}")

    if args.mode == "verify":
        rc = llm_review.main([
            "--summary", str(args.summary), "--queue", str(args.queue),
            "--context", str(args.context),
            *[part for job, path in roots.items() for part in ("--source-root", f"{job}={path}")],
            "--model", args.model, "--output", str(args.output), "--verify",
        ])
        return rc

    api_key = None
    if args.mode == "run":
        if args.key_file is None or not args.key_file.is_file():
            raise SystemExit("run mode needs --key-file pointing at a single-line key file")
        api_key = args.key_file.read_text(encoding="utf-8").strip()

    value = llm_review.run_review(
        args.summary, args.queue, args.context, roots, args.output, ids,
        allow_network=(args.mode == "run"),
        plan_only=(args.mode == "plan"),
        api_key=api_key, model=args.model, max_calls=32,
    )
    print("LLM_REVIEW_STATUS", value["status"], "; confirmed_vulnerabilities=0")
    return 0 if value["status"] in ("completed", "prepared") else 1


if __name__ == "__main__":
    raise SystemExit(main())
