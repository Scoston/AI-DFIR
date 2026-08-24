# Evidence Quality for Analysts

AI-DFIR quality states:

```text
MISSING
PRESENT_UNVALIDATED
VALIDATED
CORRELATED
AUTHORITATIVE
CONFLICTING
STALE
INCOMPLETE
```

## Practical meaning

**PRESENT_UNVALIDATED** means a file exists but has not met the integrity,
format, attribution, time, or acquisition requirements needed by the Evidence
Pack.

**VALIDATED** means the modeled checks passed.

**CORRELATED** means validated evidence has independent corroboration under a
verified acquisition/trust record.

**AUTHORITATIVE** means the source is designated authoritative and that source
claim is backed by verified signed acquisition trust.

`CONFLICTING`, `STALE`, and `INCOMPLETE` never satisfy a conclusion gate.

## Analyst rule

A filename match is not evidence sufficiency. Read the reason for any
`PRESENT_UNVALIDATED` status before using the artifact in a report.
