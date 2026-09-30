# Local vulnerability knowledge base contract

The knowledge base is a versioned local JSON file. It is never fetched from the network by the scanner.

Each record contains a CVE identifier, one or more CWE identifiers, component, affected versions, fixed versions, summary and source. Loading validates every record and emits a deterministic `records_sha256` for the complete record array.

Matching is deterministic. Exact component and affected version matches are `exact`; a known component without an exact version is `unresolved` and remains a candidate for human review. Matches carry both the database digest and source record digest.

A match is evidence for triage only. It does not prove that the current source is vulnerable, that a branch is affected, or that an OpenHarmony security report should be submitted.
