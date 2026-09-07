# Pinned raw-evidence reassessment and offline replay

Development profile: `v17_evidence_validation.assess@1.7`. This eleventh fixed
adapter reads retained evidence bytes and recomputes explicit byte, parse,
literal-text, and top-level record-field checks under independently pinned rules.
It complements [recorded Evidence Pack gate replay](EVIDENCE_PACK_REPLAY_V1.7.md),
which continues to use the original quality ratings without rescanning evidence.

## Separate the results

| Result | Meaning |
| --- | --- |
| `validation_status: SATISFIED` | This byte sequence satisfies these bounded retained rules |
| `validation_status: NOT_SATISFIED` | At least one rule failed or could not be established |
| Replay `PASS` | The complete recorded assessment matches a fresh computation, including failed validation |
| Signed case integrity `PASS` | Existing package, ledger, checkpoint, and configured trust gates passed |
| Source authority, quality promotion, attribution, time coverage, or conclusion | Remains a separate assessment; none is granted here |

`raw_evidence_reassessed` is true. `quality_rating_changed`,
`rules_approval_verified`, `source_authenticity_verified`, `attribution_verified`,
`closure_authorized`, and `network_required` are false. Collection completeness
remains unknown. A pin establishes rules identity, not organizational approval.
An expected evidence digest establishes byte agreement, not provider truth.

## Explicit formats

| Format | Parsing and record scope |
| --- | --- |
| `json-object` | Exactly one JSON object, treated as one record |
| `json-array` | A JSON array in which every element is an object |
| `jsonl` | LF-delimited object records; CRLF supported; ASCII space/tab/CR-only empty lines skipped |
| `text` | Exact strict UTF-8 decoding; no record-field rules |
| `binary` | Exact bytes, size, and expected digest; no parser or text/record rules |

JSON uses a strict bounded [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html)
profile with duplicate decoded keys, non-JSON constants, invalid UTF-8/surrogates,
and malformed structures rejected. Original number tokens are retained internally
using the existing [lossless numeric tokenizer](LOG_ANALYTICS_LOSSLESS_V1.7.md).
Numbers are classified as JSON numbers without floating-point rounding; this
does not validate a provider-specific numeric range. No values are emitted in
the field report. CSV, archives, documents, compressed content, arbitrary schema
URLs, executable validators, and nested record selection are unsupported.

Every record is checked. There is no first-100-row sampling or skipping malformed
records to create a passing result. A `json-object` envelope is one record; the
adapter does not silently extract an `entries`, `Records`, or `tables` array.

## Retain the full rules document

All fields below are required, including explicit empty lists and Booleans:

| Rule | Contract |
| --- | --- |
| `schema` | `ai-dfir/raw-evidence-rules/v1.7` |
| `case_id` | Explicit case identity, equal to the signed ledger during replay |
| `format` | One format from the table above |
| `expected_sha256` | Exact evidence-byte SHA-256; 64 lowercase hexadecimal characters |
| `min_size_bytes`, `max_size_bytes` | Integer inclusive limits, with 0 ≤ minimum ≤ maximum ≤ 8 MiB |
| `require_records` | Require at least one record; false for text/binary |
| `required_fields` | Unique top-level field names required in every record; each also appears in `field_types` |
| `field_types` | Field name → nonempty unique list of allowed JSON kinds |
| `allow_extra_fields` | Whether fields absent from `field_types` can satisfy the rules |
| `required_text` | Unique exact, case-sensitive literal strings required in decoded source text |

Allowed kinds are `array`, `boolean`, `null`, `number`, `object`, and `string`.
Numeric strings, Booleans, numbers, null, and missing fields remain distinct.
Field rules inspect top-level presence and kinds; nested structure, numeric
ranges, timestamp semantics, and business meanings are not inferred. Optional
fields may be absent; if present, their declared kind is still checked. Empty
record sets satisfy per-record field rules vacuously, so use `require_records`
when an empty set must fail. No empty set proves coverage.

Text matching is literal, without regex, case folding, Unicode normalization,
replacement decoding, or JSON unescaping. In JSON formats it searches the decoded
source text, not reconstructed string values. Binary rules require an empty
text list. Text/binary rules require empty field rules and `allow_extra_fields`
true. Empty text/binary evidence can satisfy a deliberately zero minimum; its
empty content is still digest-bound. Empty JSON is an invalid JSON profile.

There are at most 64 required names, 64 type declarations, and 64 text literals.
Names contain 1–256 characters, literals 1–4,096; control characters are rejected.
Unknown fields, duplicated rules, unsupported kinds, mismatched case identity,
and missing or mismatched rules pins fail before an assessment is returned.

## Field-schema observations

Each field is identified by the SHA-256 of its canonical JSON name. The report
records observed kinds, presence counts, missing-required counts, type-mismatch
counts, and whether the name is unexpected under the retained rules. Analysts
can resolve names using the retained rules; arbitrary evidence field names and
payload values are not echoed in the report.

`observed_schema_sha256` fingerprints the sorted observed field identities and
kind sets. Changing only values, record order, or record count preserves this
fingerprint; changing an observed field or kind changes it. Exact source hashes
still bind every byte and distinguish those different source files. This is
automatic top-level schema observation, not a complete provider schema, proof of
schema compatibility, or measurement of uncollected sources. Presence counts
refer only to the complete parsed input record set, never the incident universe.

For deeper retained comparisons, the separate [nested schema adapter](NESTED_SCHEMA_DRIFT_V1.7.md)
observes member/array paths and kind/count changes under an explicit baseline-byte
pin. It does not change this adapter's top-level field rules or promote evidence
quality, provider schema authority, or source coverage.

## Local assessment and comparison

Prepare and retain rules as an operator decision, including the expected evidence
digest and any approved field constraints. Independently retain their RFC 8785
canonical SHA-256. The tool never silently adopts a pin from an untrusted input.

```bash
python evidence_validation_v17.py --input retained-evidence.dat \
  --rules retained-rules.json --case CASE-001 \
  --expected-rules-sha256 <canonical-rules-digest> --out new-assessment.json
python evidence_validation_v17.py --input retained-evidence.dat \
  --rules retained-rules.json --case CASE-001 \
  --expected-rules-sha256 <canonical-rules-digest> --compare recorded-assessment.json
```

Inputs must be bounded regular files. The evidence reader accepts zero bytes so
the rules can assess them; rules and recorded assessments remain nonempty JSON.
Output creation is exclusive and never overwrites raw evidence, rules, existing
assessments, or symlink targets. Errors are redacted. Source/rules bytes, payload
values, field names, literals, and local paths are not echoed on stdout.

Assessment exits 0 for `SATISFIED`, 2 for a written `NOT_SATISFIED` assessment,
and 1 for invalid configuration or input/output failure. Comparison exits 0 for
matching replay, even when reproducing `NOT_SATISFIED`, and 1 for mismatch/error.
Do not interpret the comparison exit alone as evidence sufficiency.

## Signed offline replay

Retain evidence, rules, and assessment as three separate case artifacts. Bind a
`derived-from` relationship from evidence to assessment with transformation
`v17_evidence_validation.assess`, version `1.7`, and metadata:

```json
{"rules_artifact_id":"VALIDATION-RULES","rules_sha256":"<canonical-rules-digest>"}
```

The rules reference is a distinct bound artifact and a second lineage input,
including cycle detection. Existing signature, inventory, checkpoint, and
configured independent gates run before replay. Case identity comes from the
verified ledger. The fixed adapter cannot invoke arbitrary code, shell commands,
models, network schemas, file discovery, or live collectors. Unknown versions
remain unsupported. Replay remains explicitly requested.

The complete canonical assessment is compared. It includes exact evidence and
rules-byte hashes as well as the canonical rules pin, every check, field counts,
and claim limitations. Reformatting otherwise equivalent rules preserves the
canonical pin but changes the exact rules-byte binding. Re-signing substituted
bytes, weakened rules, or a falsely promoted result cannot reproduce the old
assessment. Historical recorded quality ratings remain untouched.

## Limits and acceptance

Raw evidence is at most 8 MiB; rules and output are each at most 256 KiB. JSON
has the shared depth-32 and 200,000-node budgets, including a global walk across
JSONL records. At most 10,000 object records, 20,000 LF separators, 1 MiB per
physical JSONL line, 256 distinct observed names, and 128 characters per number
token are supported. The global array walk counts the record-list wrapper.

Malformed or unsupported evidence returns `NOT_SATISFIED` with
`parse_state: INVALID_OR_UNSUPPORTED`; record/field observations are cleared,
so there is no partial-success sample. Invalid rules, oversized raw byte input,
or excessive output fail the operation. No archive/document extraction occurs.

Synthetic acceptance covers all five formats, matching failed validation, and
detection of a falsely promoted assessment in a re-signed case. The 190 focused
regressions include strict bounds, exact numeric kinds, every-record checks,
schema fingerprints, independent pins, signed empty evidence, lineage and trust
gates, offline execution, and CLI preservation. Source/extracted-package gates
and conditional independent package verification require these files and checks.
This adds no detector, production validation, or new Evidence Pack conclusions;
existing catalog gates and quality ratings remain separate.
