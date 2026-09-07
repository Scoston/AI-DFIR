# Nested schema observations and pinned baseline comparison

Development profile: `v17_schema_drift.compare@1.7`. This twelfth fixed replay
adapter compares the complete nested JSON structure observed in two retained
inputs. The baseline has an explicit independent SHA-256 pin. It extends the
[top-level field observations](RAW_EVIDENCE_REASSESSMENT_V1.7.md) with nested
member/array paths, per-kind occurrence counts, record presence, and signed
offline reproduction of the full comparison.

## Interpret the result

| Field | Meaning |
| --- | --- |
| `drift_status: CHANGED` | At least one observed path or JSON-kind set was added, removed, or changed |
| `drift_status: UNCHANGED` | Both retained populations exhibit the same observed path/kind sets |
| `bytes_changed` | The two exact byte sequences differ |
| `population_counts_changed` | Record count, observed path population, or path/kind occurrence counts differ |
| Replay `PASS` | The full recorded comparison reproduces, including any observed drift |
| `provider_schema_change_proven` | Always false; different retained populations do not prove a provider changed its contract |

Adding a record, removing optional metadata, seeing a previously empty array,
or encountering a nullable value can change the observed shape. These are
observations about these files. They do not prove provider schema evolution,
backward compatibility, source coverage, successful acquisition, or evidence
quality. Value-only changes and changed record counts can preserve the same
shape fingerprint. Exact byte hashes and separate counts retain those differences.

`source_authenticity_verified`, `baseline_approval_verified`,
`schema_compatibility_verified`, `quality_rating_changed`, `closure_authorized`,
and `network_required` are false. `collection_complete` is unknown. A baseline
pin establishes its byte identity, not organizational approval or source truth.
The current native provider parsers remain the appropriate separate profiles for
provider-specific field semantics, numeric ranges, and timestamps.

## Explicit record scope

| Format | Scope |
| --- | --- |
| `json-object` | One top-level object is one record; all nested members and arrays are observed |
| `json-array` | Every top-level element must be an object; each is one record |
| `jsonl` | LF-delimited object records, with CRLF and ASCII space/tab/CR-only blank lines supported |

An entire provider response envelope can be compared as `json-object`. Its nested
event array is observed without silently redefining which elements are records.
For that format, `present_records` is at most one, while nested occurrence counts
can be larger. Array and JSONL formats use their explicit top-level object records.
Every retained record and nested node is observed; there is no first-100-record
sample or malformed-record skipping.

Strict bounded parsing rejects duplicate decoded keys, invalid UTF-8/surrogates,
non-JSON constants, excess number tokens, malformed records, and exceeded budgets.
Numbers retain their original tokens internally; a number remains distinct from
a numeric string or Boolean. This observation profile does not validate numeric
ranges. String contents, including JSON embedded inside strings such as a
LookupEvents `CloudTrailEvent`, remain strings and are not recursively parsed.
Archives, compressed input, CSV, documents, external schemas, executable
validators, and inferred provider formats are unsupported.

Empty arrays and empty/blank JSONL inputs have zero observed records and no paths.
An empty object is one observed object record. Moving between an empty population
and an observed record can change the shape but never establishes missing-source
coverage. Empty raw bytes are valid only for the explicitly selected JSONL profile.

## Structured path identity and counts

Paths use typed segments instead of dot, slash, or bracket-separated names:

| Path or segment | Meaning |
| --- | --- |
| `[]` | The root of one explicit record |
| `["member", "name"]` | An exact JSON object member name |
| `["items"]` | Any element of the array at the preceding path |

A path is an ordered list of those member/items segments. Array positions collapse
to one items path; every occurrence is still counted. Field names such as `a.b`,
`a/b`, `items`, `[]`, `0`, and the empty name remain distinct from path syntax.
Names are case-sensitive and are not Unicode-normalized. Equivalent JSON escapes
decode to the same name while exact source bytes remain separately bound.

The path digest is SHA-256 of RFC 8785 canonical JSON with exact fields `schema`
(`ai-dfir/nested-schema-path/v1.7`) and `segments`. A path report contains:

- `path_sha256`: the structured identity, with no raw field name or payload value;
- `kinds`: the sorted observed set of array, boolean, null, number, object, or string;
- `occurrences` and `kind_occurrences`: all observed instances, including repeated array elements;
- `present_records`: the number of distinct explicit records containing that path at least once.

Resolve a known path using the retained input and the helper, for example:

```python
from v17_schema_drift import path_sha256
identity = path_sha256([
    ["member", "protoPayload"],
    ["member", "authorizationInfo"],
    ["items"],
    ["member", "granted"],
])
```

Reports sort paths by digest. Shape fingerprints bind the shape schema version,
explicit input format, and sorted path/kind sets. They omit values and counts.
The comparison separately lists added/removed path identities and changed kind
sets. Baseline/current observations preserve complete counts. Field names and
payloads remain in the retained evidence rather than being echoed in reports.

## CLI and signed replay

Independently approve and retain the baseline bytes and their exact SHA-256.
The following commands assume that pin is already in `SCHEMA_BASELINE_SHA256`:

```bash
python schema_drift_v17.py --input current-export.json --baseline baseline-export.json \
  --expected-baseline-sha256 "$SCHEMA_BASELINE_SHA256" \
  --format json-object --case CASE-001 --out nested-comparison.json

python schema_drift_v17.py --input current-export.json --baseline baseline-export.json \
  --expected-baseline-sha256 "$SCHEMA_BASELINE_SHA256" \
  --format json-object --case CASE-001 --compare nested-comparison.json
```

New comparisons exit 2 when shape drift is observed and 0 when shape is unchanged.
Both can successfully produce a complete comparison. Replaying either exits 0 if
the full recorded comparison matches and 1 if it differs. Invalid/unavailable,
untrusted, excessive, or conflicting inputs/outputs exit 1; interruption exits 130.
Inputs use bounded regular-file reads. New output uses exclusive mode-0600 creation
and cannot overwrite sources, a baseline, existing reports, or symlink targets.
Failures are redacted. Treat an interrupted/failed output write as incomplete and
retry into a new path.

For signed case replay, retain three distinct artifact records: current input,
baseline input, and complete comparison. The derived-from relationship uses the
current input as parent and the comparison as child, with exact metadata:

```json
{
  "input_format": "json-object",
  "baseline_artifact_id": "SCHEMA-BASELINE",
  "baseline_sha256": "<independently retained exact baseline-byte SHA-256>"
}
```

The baseline must reference a distinct artifact in the same validated provenance
profile and participates as a second input in lineage-cycle detection. Replay
takes case identity from the verified ledger and checks the explicit baseline
pin before comparison. Existing inventory, signature, checkpoint, timestamp, and
configured trust gates run first. Unsupported versions are never dynamically
loaded, and comparison remains opt-in. Re-signing substituted source/baseline
bytes, pins, counts, shape digests, or unsupported approval claims does not make an
old comparison reproduce. Identical bytes may occupy distinct artifact records.

## Bounds and acceptance

Each input is at most 8 MiB and 10,000 records. JSONL additionally has at most
20,000 LF separators and a 1 MiB per-line limit. Shared parsed-tree limits apply
globally across all records: depth 32 and 200,000 nodes, including the record-list
wrapper. Each observation has at most 1,024 unique paths, including an observed
record root. Member names are at most 1,024 UTF-8 bytes; the encoded path identity
is at most 16 KiB and 32 segments. The full comparison is at most 1 MiB. Exceeding
any limit produces no partial successful comparison.

The 182 regressions include all JSON-kind transitions, exact structured path
identities, array/record counts, record 201 changes, numeric spelling, empty signed
JSONL inputs, byte/path/record/depth/node limits, wrong baseline pins, signed
substitution, second-input cycles, independent verification gates, and CLI output
preservation. Source and extracted release gates require both synthetic signed
acceptance and all regressions; conditional independent package verification
requires the complete profile and assurance fields. There is no live provider
query, authoritative baseline discovery, or automatic Evidence Pack gate promotion.
