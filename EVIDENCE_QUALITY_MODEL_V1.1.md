# AI-DFIR v1.1 Evidence Quality Model

## Why this changed

Earlier releases correctly treated missing evidence as unknown, but a matching
filename could still satisfy an Evidence Pack requirement.

v1.1 removes that shortcut.

## Quality ladder

```text
AUTHORITATIVE
    Independent provider/system-of-record evidence or explicitly authoritative
    acquisition record.

CORRELATED
    Validated evidence corroborated by an independent source.

VALIDATED
    Present, parseable, internally plausible, attribution/time/integrity checks
    required by the Evidence Pack have passed.

PRESENT_UNVALIDATED
    A matching artifact exists but one or more validation requirements are not
    met.

MISSING
    No matching artifact.

CONFLICTING
STALE
INCOMPLETE
    Present evidence that must not satisfy a conclusion gate.
```

## Validation dimensions

Artifact requirements may test:

- minimum/maximum size
- JSON/JSONL/CSV/text parseability
- required records
- required fields/text
- acquisition SHA-256
- source host/user/agent attribution
- incident-window coverage
- completeness/staleness/conflict flags
- authoritative/corroborated acquisition status

## Conclusion gates

A conclusion may require different evidence quality per artifact:

```text
Injection observed
  transcript >= VALIDATED

Impact confirmed
  tool trace >= VALIDATED
  target audit >= CORRELATED
```

## Acquisition manifest

`ACQUISITION_MANIFEST.json` is the bridge between a copied file and a forensic
artifact. It can bind the file to:

```text
original path
SHA-256
source host/user
source type
coverage period
clock offset/uncertainty
filesystem inode/device/link metadata
xattr hashes
authoritative/corroborated status
```

## Analyst workflow

If evidence is present but below quality, `evidence_tasks.py` now creates a
`VALIDATION_REQUIRED` task instead of treating the requirement as complete.
