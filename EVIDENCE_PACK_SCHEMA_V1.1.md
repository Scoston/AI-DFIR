# AI-DFIR Evidence Pack Schema v1.1

v1.1 changes Evidence Pack sufficiency from **file presence** to **evidence quality**.

## Quality states

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

`CONFLICTING`, `STALE`, and `INCOMPLETE` never satisfy conclusion gates.

## Artifact validation

An artifact can include:

```json
{
  "id": "tool_trace",
  "priority": "mandatory",
  "presence_patterns": ["*tool*.jsonl"],
  "validation": {
    "min_size_bytes": 1,
    "format": "jsonl",
    "require_records": true,
    "must_contain_fields": ["event_id", "event_type"],
    "require_acquisition_hash": true,
    "require_attribution": true,
    "require_time_attribution": true,
    "must_cover_entire_window": false
  }
}
```

## Acquisition metadata

`ACQUISITION_MANIFEST.json` can bind a matched artifact to:

```text
SHA-256
source host
source user
source agent
coverage start/end
clock offset
clock uncertainty
authoritative/corroborated flag
incomplete/stale/conflicting flag
filesystem metadata
```

## Conclusion gates

Conclusion gates may define a minimum quality:

```json
{
  "id": "impact",
  "logic": "all",
  "requires": ["tool_trace", "target_audit"],
  "min_quality": "VALIDATED",
  "quality_requires": {
    "target_audit": "CORRELATED"
  }
}
```

Presence alone cannot support a conclusion in v1.1.
