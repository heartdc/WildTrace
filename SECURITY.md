# Security policy

WildTrace is a defensive, local-only source auditing project.

## Scope

Authorized local source and fixed versions are in scope. Target execution is
disabled by default. The project does not scan internet targets, probe remote
services, generate weaponized payloads, or submit reports automatically.

## Explicit local case validation

The project owner has explicitly authorized real local validation in this
conversation. The case-specific cJSON reproducer may be run only by an explicit
`--execute-authorized` invocation inside its mandatory namespace sandbox, using
the pinned source copies, fixed tiny inputs and fresh output directory. No host
root/home/network mounts or unsandboxed fallback are allowed. Source trees are
not patched in place. This narrow authorization is not permission to attack a
device, public endpoint, unknown product or another party's data. Tool execution
checks remain binding; a blocked tool action must not be rerouted.

Prepared code, successful compilation and valid records are not runtime proof.
Only observed results may fill runtime fields. Separate builds by one operator
are not independent human review, and a library reproducer does not establish a
product's reachable attack path or a new vulnerability discovery.

## Optional remote drafting

Only an explicit user-authorized LLM run may send selected, bounded diagnostic
metadata and source windows to an allowlisted HTTPS endpoint. This exception is
limited to remote drafting: normal scans, review planning and offline verification
remain local. It does not authorize executing target code or model-generated
commands, uploading a whole repository, submitting reports or persisting API keys.
Model output is untrusted, references are validated locally, and vulnerability
status cannot be upgraded by a model. Provider errors must not expose credentials.

## Candidate interpretation

Scanner output is a candidate for human review. It is not a vulnerability verdict or an OpenHarmony platform impact claim. Do not include secrets, personal data, or real exploitation instructions in issues or test fixtures.

## Reporting

This repository does not automatically submit reports or bounty claims. Use the project owner’s private review process for authorized findings.
