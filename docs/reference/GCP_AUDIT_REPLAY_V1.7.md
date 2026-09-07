# Google Cloud Audit Logs import and offline replay

This development profile is unreleased. It projects selected recorded audit
metadata from retained native JSON and compares that projection offline.
It does not collect logs or authenticate Google as their source.

## Input profiles

Choose the input format explicitly:

| Format | Input | Pagination |
|---|---|---|
| `entries` | A retained `entries.list` response with only `entries` and optional `nextPageToken` | A nonempty token reports incomplete collection |
| `array` | A JSON array of native LogEntry objects, such as retained `gcloud logging read --format=json` output | Collection coverage remains unknown |

An omitted entries list is accepted as empty, including a response containing
only a next-page token. Null or incorrectly typed lists fail. Empty responses
never establish that an activity did not occur. Empty and absent tokens are
distinguished by their recorded digest state, and token values are not copied
into output.

Every entry needs a native `protoPayload` with
`@type: "type.googleapis.com/google.cloud.audit.AuditLog"`, a timestamp, a monitored
resource object/type, service and method names, and an audit log name. The
supported URL-encoded audit log names end in activity, data_access, system_event,
or policy, under projects, organizations, folders, or billingAccounts.

Entries with text/json payloads, mixed payloads, or any split marker fail.
The parser does not assemble split entries. JSONL, compressed input, Pub/Sub
envelopes, Cloud Storage export layouts, non-audit logs, and combined collector
page envelopes are outside this profile. Preserve original acquisitions and
any separately authorized transformations in their own lineage.

Google documents the [LogEntry structure and timestamp precision](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry),
[AuditLog fields](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog),
[entries.list responses](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list),
and [gcloud logging read](https://docs.cloud.google.com/sdk/gcloud/reference/logging/read).
The existing live collector and legacy flat-row normalizer keep their behavior.

## Commands

```bash
python gcp_audit_v17.py --input retained-response.json \
  --format entries --out audit-projection.json

python gcp_audit_v17.py --input retained-array.json \
  --format array --out array-projection.json

python gcp_audit_v17.py --input retained-response.json \
  --format entries --compare audit-projection.json
```

Inputs must be bounded regular files. Output creation is exclusive; existing
files are preserved. A malformed entry rejects the entire document, without
skipped rows or a partial projection. CLI exit 0 means normalization/comparison
succeeded; exit 1 means an input, output, budget, or comparison failure. Invalid
command syntax uses argparse exit 2. Error reports omit evidence text and paths.

No network request, model, subprocess, provider SDK, catalog lookup, or
evidence-selected import is performed.

## Recorded metadata and its limits

The source digest binds the exact input bytes. Each entry has a separate
RFC 8785 canonical digest. Input order, duplicate insert IDs, repeated permission
records, and delegation order are retained with one-based ordinals. Missing
insert IDs remain null; no identity or causal sequence is invented.

Event and receive timestamps retain their original strings, including up to
nine fractional digits and explicit offsets. Calendar/offset syntax is checked
without converting fractional seconds to floating point or microseconds.
Leap-second spellings and timezone-free timestamps fail. No clock accuracy,
UTC conversion, chronological sorting, or event-to-receipt ordering is inferred.

The projection preserves log scope/category, service, method, target resource,
monitored resource type/digest, caller IP, trace/span IDs, and selected identity
fields. The log's owning scope and the operation's target resource remain
separate; cross-project records are not silently rewritten.

Caller principal email, subject, and authority selector are separate from
delegated first-party emails and third-party subjects. Each delegation record
has its own digest. First-party service metadata and third-party claims are
hashed. Ambiguous records containing both authority variants fail. The parser
does not identify which principal was a human decision-maker or authenticate
delegation, credentials, or entitlement.

Each permission record retains its resource, permission, explicit granted value,
and resource-attribute digest. Missing granted values remain null. Status
presence, explicit integer status code, and operation first/last markers are
recorded separately. A missing/default-omitted field is not populated with an
assumed value. No aggregate authorization, successful action, finished operation,
or downstream effect is inferred from these fields.

Opaque request, response, metadata, service data, original resource state,
resource location, policy violations, authentication/authorization information,
request metadata, and status are hashed. Digest state distinguishes absent,
explicit null, and present content. Interpreted identity/status/list fields
must have the expected types when present; null is not coerced into a typed
object or list. Unknown fields remain bound by the canonical entry digest.
This is a strict projection profile, not a complete Protobuf JSON validator.

Prompt bodies, error text, service-account key references, and third-party
claims are not deliberately copied into the projection. Selected metadata can
still contain sensitive information. This tool is not a general redaction or
declassification service, and preserved raw artifacts retain their original
content.

A nonempty nextPageToken sets collection_complete to false. Otherwise it stays
null, including for empty results. Query limits, filters, earlier pages, logging
configuration, retention, redaction, and missing streams remain unknown.
Google's [audit logging overview](https://docs.cloud.google.com/logging/docs/audit)
describes source-dependent availability and identity redaction. The parser cannot
recover uncollected evidence or turn an absent identity into attribution.

source_authenticity_verified remains false. Successful parsing or matching
replay establishes reproducibility of retained data, not provider origin,
complete collection, human attribution, permission legitimacy, or incident closure.

## Signed-case integration

Preserve the raw export and projection as separate EvidenceArtifact records in
the same case. Ledger-bind an EvidenceRelationship from the raw parent to the
projected child with the existing required case, artifact IDs, and timestamp:

```json
{
  "relationship_type": "derived-from",
  "transformation": "v17_gcp_audit.normalize",
  "transformation_version": "1.7",
  "metadata": {"input_format": "entries"}
}
```

Use `array` for the array profile. Metadata must contain exactly input_format.
Follow [Investigation replay](INVESTIGATION_REPLAY_V1.7.md) to bind all records,
sign the completed ledger, and export through the authorized signing workflow.

```bash
python replay_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --replay-transforms --out replay.json
```

Reconstruction uses verified bytes from the same open archive without extraction.
Unknown transform versions produce UNSUPPORTED and requested replay INCOMPLETE.
An integrity-valid signed case with an incorrect projection produces replay
FAIL. Both conditions cause requested replay to exit 1. Current trust, timestamp,
and other required case gates remain independent and can block reconstruction.

Comparison covers the entire projected JSON using RFC 8785. Projection whitespace
may change; raw-file whitespace changes its exact source digest and requires a
new projection. Recorded timestamps and delegation/permission order are included.

## Bounds and acceptance

Input and output each have an 8 MiB cap; at most 2,000 entries are accepted, each
with at most 1 MiB of canonical JSON. Parsed trees allow 32 levels and 200,000
nodes, including keys. Input and output have separate node budgets. Metadata
strings allow 4,096 characters; each entry allows up to 64 delegation records and
256 permission records. All limits apply together.

Duplicate keys, invalid UTF-8, unpaired surrogates, non-finite numbers, integers
outside RFC 8785's safe range, invalid typed fields, mixed envelopes, and exceeded
budgets fail. Explicit status codes must be JSON integers in the signed 32-bit
range; their numeric meaning is not used to infer an outcome.

```bash
python v17_gcp_audit_selftest.py
python -m pytest tests/test_v17_gcp_audit.py -q
python scripts/release_check.py --full
```

The synthetic acceptance verifies both native formats in signed cases and
detects an incorrectly recorded permission decision. The 163 focused regressions
cover offline execution, nanoseconds, delegation and identity distinctions,
permission/status uncertainty, hostile JSON, budgets, pagination, CLI behavior,
archive tampering, and independent case gates. Source and extracted-package
assurance require the same profile files, tests, and self-test. Historical
v1.7.0 package verification remains supported.


## Optional request-context capture

The separate [Google Cloud Logging capture profile](GCP_LOGGING_CAPTURE_V1.7.md)
binds one entries.list request and its exact Audit Log response bytes into signed
offline replay. It retains ordered resource, filter, sort, and pagination
assertions without changing this native response projection or claiming effective
scope, prior-page coverage, provider origin, or complete collection.
