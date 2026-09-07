# Azure Activity Log import and offline replay

This development profile is unreleased. It projects selected recorded metadata
from retained native Activity Log JSON and compares that projection offline.
It does not collect logs or authenticate Microsoft as their source.

## Input profiles

Select the format explicitly:

| Format | Input | Pagination |
|---|---|---|
| `activity-log` | A retained REST EventDataCollection with required `value` array and optional `nextLink` only | A nonempty continuation link reports incomplete collection |
| `array` | A preserved JSON array of native EventData objects | Collection coverage remains unknown |

Empty arrays are accepted. Missing `value`, null lists, nonobject rows, mixed
envelopes, or invalid events fail the whole import. No events are silently skipped.
An absent, null, or empty nextLink does not establish complete collection. Their
digest states remain distinct. Nonempty links are hashed, never copied into the
projection, followed, resolved, or used as file paths. Array input has no
pagination inference. Preserve acquisition scope, filters, and other pages
separately; an empty export does not establish that an activity never occurred.

Each event requires nonempty `eventDataId`, `eventTimestamp`, and
`operationName.value`. Resource, caller, and submission time may be absent for
sparse events. This strict profile accepts absent interpreted objects, but a
present claims, authorization, httpRequest, or localizable field must be an
object. Optional invariant/translated label values may be null, as in native
health/alert events; explicit field states distinguish absence, null, and empty
text. Required operationName.value remains a nonempty string. Other selected
metadata strings reject null or nonstring values and are never filled from other
fields.

Log Analytics `tables`/columns/rows responses (including output retained by the
existing `azure_foundry_logs` collector), Event Hub/storage-transformed layouts,
combined page wrappers, JSONL, compression, and bare singleton events are outside
this profile. They need separate parsers and preserved transformation lineage.
Use the implemented [Log Analytics query-result profile](LOG_ANALYTICS_REPLAY_V1.7.md)
for native tables. That separate extension also corrects Azure collector
completeness metadata; this Activity Log parser and legacy flat-row normalization
retain their existing behavior.

Microsoft defines the native collection, EventData, LocalizableString, and
HttpRequestInfo structures in the [Activity Logs REST reference](https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list?view=rest-monitor-2015-04-01).
The [Activity Log schema guide](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema)
describes management-plane event categories and recorded identity/authorization
fields. Activity Log context does not establish model invocation or data-plane
request coverage. The separate [Log Analytics response format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format)
uses typed columns/rows and can include partial errors; it is not treated as an
Activity Log REST envelope.

## Commands

```bash
python azure_activity_v17.py --input retained-response.json \
  --format activity-log --out activity-projection.json

python azure_activity_v17.py --input retained-array.json \
  --format array --out array-projection.json

python azure_activity_v17.py --input retained-response.json \
  --format activity-log --compare activity-projection.json
```

The CLI reads bounded regular files and creates output exclusively, preserving
existing destinations, source files, and symlink targets. Comparison and creation
success exit 0; invalid inputs, unavailable files, conflicting destinations, and
comparison failure exit 1. Malformed arguments exit 2. Runtime error reports omit
raw content and paths. The output contains selected identities and resource
metadata, so apply the case's access controls to it as well as to the raw source.

## Recorded observations and limits

- Exact input bytes have a source SHA-256. Each complete native event has an RFC
  8785 canonical digest, including unknown fields. Event order, duplicates, and
  conflicting eventDataId values remain intact with one-based ordinals.
- eventTimestamp and submissionTimestamp remain separate original strings,
  preserving explicit offsets and up to nine fractional digits, including
  Azure's seven-digit examples. Calendar and offset checks do not round, convert
  to UTC, sort events, or infer clock correctness or causal order. Leap-second
  spelling and missing offsets are unsupported.
- Invariant `value` and `localizedValue` remain separate for operationName,
  eventName, category, resourceProviderName, resourceType, status, and subStatus.
  A translation never fills an absent or null invariant value. Operation name and event
  name remain distinct; status does not prove downstream effects or closure.
- Caller, application/object/tenant/type claims (`appid`, `oid`, `tid`, `idtyp`),
  the full-URI objectidentifier/tenantid/nameidentifier claims, and event tenantId
  remain distinct. Aliases are not coalesced or resolved, even if contradictory.
  These are recorded claims, not authenticated identities or human attribution.
- Authorization action/role/scope and HTTP request ID, IP, and method are retained
  as observations. Authorization metadata is not independent proof of permission
  or human approval. Correlation and operation IDs do not join, deduplicate, or
  establish causality among events.
- Full claims, authorization, HTTP request, properties, and description values
  are digest-bound. Opaque properties/description and URI content are not parsed
  or copied. Their absent/null/present states remain distinguishable. Hashing
  content does not redact the retained original or authenticate its origin.

## Signed-case integration

Preserve the raw export and projection as separate EvidenceArtifact records in
the same case. Ledger-bind an EvidenceRelationship from the raw parent to the
projected child with the existing required case, artifact IDs, and timestamp:

```json
{
  "relationship_type": "derived-from",
  "transformation": "v17_azure_activity.normalize",
  "transformation_version": "1.7",
  "metadata": {"input_format": "activity-log"}
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
Evidence cannot select a command, import, model, network destination, or plugin.

Comparison covers the entire projected JSON using RFC 8785. Projection whitespace
may change; raw-file whitespace changes its exact source digest and requires a
new projection. Recorded timestamps, claim aliases, translations, and order are
part of the comparison. Replay proves only the specified projection was reproduced.

## Bounds and acceptance

Input and output each have an 8 MiB cap; at most 2,000 events are accepted, each
with at most 1 MiB of canonical JSON. Parsed trees allow 32 levels and 200,000
nodes, including keys. Input and output have separate node budgets. Selected
metadata strings allow 4,096 characters. All limits apply together; a collection
below the event count cap may still exceed the output or structure budget.

Duplicate keys, invalid UTF-8, unpaired surrogates, non-finite numbers, integers
outside RFC 8785's safe range, invalid typed fields, mixed envelopes, and exceeded
budgets fail. Unknown event fields are still bounded and included in its digest.

```bash
python v17_azure_activity_selftest.py
python -m pytest tests/test_v17_azure_activity.py -q
python scripts/release_check.py --full
```

Synthetic acceptance verifies both formats in signed cases and detects incorrect
identity projection. The 207 focused regressions cover offline execution,
timestamp precision, identity/label/status distinctions, hostile JSON, budgets,
pagination, source preservation, archive tampering, and independent case gates.
Source and extracted-package assurance require the same profile files, tests,
and self-test. Historical v1.7.0 package verification remains supported.
