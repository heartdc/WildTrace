# Explicit LLM review of verified evidence

`ohvul.llm_review` adds bounded model proposals after the existing batch, review
queue and source-context checks. It does not replace those checks or change the
workflow FSM. A schema-valid draft is not an independently verified analysis.

## Endpoint and credentials

The default base URL is `https://oslovelace.com/v1`, with the caller-selected
provider model identifier `grok-4.6`. The historical www hostname remains an
explicit allowlisted alternative for compatibility; no automatic fallback is
performed. HTTPS certificate verification remains enabled. Redirects are rejected.
Keys are read from `OSLOVELACE_API_KEY`, or from a non-echo stdin pipe with
`--key-stdin`. There is no key command-line argument, config file or saved key.
Do not put a credential in scripts, reports, README, Git, command histories or
model prompts. Python strings are not guaranteed to be securely erased in memory.

Ordinary scanning, planning and independent verification make no model request.
Remote execution requires both `--run` and `--allow-network`. The latter grants
permission to send only the selected diagnostic metadata and code windows to
the explicitly selected provider. It is not permission for target execution,
full-repository upload, downloading tools or automatically submitting reports.

## Input and output contract

The caller supplies the exact saved batch summary, queue and context documents,
plus one independent `--source-root JOB=PATH` argument per job. All existing
queue/context validations run before sending evidence. Source snapshots and
input bytes are checked again before accepting the run.

Each `--group` must be an existing distinct group. No default first-N selection
silently discards the remaining queue. Planning records the selected count and
the queue groups not selected. The current per-run maximum is 32 calls; defaults
are three calls and 2048 requested output tokens per call. `--max-tokens` accepts
128–4096; `--timeout` accepts integer seconds from 1–120 (socket timeout, not a
guaranteed total wall-clock deadline). There are no automatic retries. Any
transport error stops subsequent selected requests, recording them as `not_run`.

Requests exclude absolute local source-root paths and analyzer command lines.
Only relative locations, bounded source lines, diagnostic summaries and evidence
identifiers are sent. Known credential patterns and the runtime credential are
screened before requests and before response persistence. This is a conservative
leak screen, not a complete secret-classification system.

The model answers the five existing questions: `reachability`, `input_control`,
`bounds_and_lifetime`, `security_impact`, and `independent_validation`. Every
local observation must cite supplied line/diagnostic reference IDs. Unknown and
unsupported evidence remains `unknown`; independent validation always remains
unknown because this stage performs no reproduction. Source/comments/strings
are labeled untrusted data and cannot define system instructions or tools.
This prompt boundary does not prove that the model cannot hallucinate.

Recommendations are `needs_context`, `manual_review`, or `lower_priority`.
None deletes a finding or changes vulnerability state. `final_verdict` is always
`undetermined`, confirmed vulnerabilities remain zero, and human review is
required. Suggestions and next checks are data, never executable commands.

A new output directory contains `plan.json`, an `item-NNNN.json` record per
selected group, and `summary.json`. Existing directories are never overwritten.
Interrupted writes or exceptions may leave an incomplete directory. The offline
verifier will not accept it as a completed run. Bad JSON, invented references,
truncation, unexpected model identifiers and unsupported claims are rejected;
raw model text remains explicitly untrusted when safely retainable.

## Commands

Choose group IDs from the verified queue. For example, save the desired command
arguments without credentials and use the same inputs in all three modes:

```powershell
python -m ohvul.llm_review `
  --summary .cache/real_components_c0d3/batch/summary-0005.json `
  --queue .cache/review_33f843/queue.json `
  --context .cache/review_33f843/context.json `
  --source-root camera_app=C:/Projects/OpenHarmony-complete `
  --source-root hilog_featured=C:/Projects/OpenHarmony-complete `
  --source-root securec=C:/Projects/OpenHarmony-complete/third_party/bounds_checking_function `
  --group RG-144ae6dddb1a53066a278e2d56a142742af2ced23bd9876d0345a972f4440930 `
  --output .cache/llm-plan-new --plan
```

For an authorized remote run, provide the key in the process environment, use a
different new output directory and replace `--plan` with `--run --allow-network`.
For offline acceptance, use the same three input documents/source-root mapping,
point `--output` at the saved run and use `--verify`. No key or network flag is
needed for verification. Verification reloads the exact prompt and evidence,
revalidates model output references and hashes, and checks summary consistency.
It is not a proof that a model's prose is correct or provider metadata authentic.

## Failure and accounting

New plans include `execution_policy=stop-on-transport-failure-1`. The offline
`--inspect` mode accepts consistent failed histories as `bound_incomplete`, while
`--verify` continues to reject unsuccessful inference. Even a rejected draft
must retain valid request/content/usage bindings. Unversioned historical plans
are explicitly labeled legacy and are not rewritten to claim the new policy.
See [offline inspection and evidence handoff](REVIEW_HANDOFF.md).

`completed` means all explicitly selected drafts passed structural, reference
and input-binding checks. It does not mean the whole queue was analyzed.
`incomplete` records failures and unused selections; the process returns nonzero.
HTTP error bodies and arbitrary exception messages are not printed or stored.
Usage is whitelisted provider-reported token data, not a billing statement.
Missing usage remains unknown; known subtotal zero is not proof of zero charges.

The first three real endpoint requests in this development run returned HTTP
403. They produced no model output or usage receipt. Further diagnostic action
was blocked by a tool safety check and was not retried by another route. No
successful online model review is claimed. See the dated LLM integration audit.

Update: after the user reported that the service was accessible locally, a
same-endpoint single-group retry was started, but tool-side credential input was
blocked before a request was sent. The waiting process was stopped. There is no
new HTTP response from that attempt; the older 403s do not establish the current
server state. No credential retransmission workaround was attempted.
