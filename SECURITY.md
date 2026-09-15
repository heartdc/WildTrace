# Security policy

WildTrace is a defensive, local-only source auditing project.

## Scope

Only authorized local source, fixed versions, and isolated synthetic harnesses are in scope. The project does not scan internet targets, probe remote services, execute target code, generate real attack payloads, or submit reports automatically. The sole scoped exception is an explicitly signed [Isolated Execution Authorization](docs/engineering/EXECUTION_AUTHORIZATION.md): until that document is signed by all owners, the no-target-execution rule above applies in full.

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
