# Log Analytics retained request context and replay

This unreleased, offline profile binds a separately retained request-context
artifact to the exact bytes of a native Log Analytics response. It reproduces
the existing typed result projection and detects a changed query, scope field,
header observation, response, or recorded projection. It never executes KQL.

The workspace POST profile below retains its original projection semantics.
The same adapter and CLI also support an explicit, separately specified
[workspace GET query/timespan profile](LOG_ANALYTICS_GET_CONTEXT_V1.7.md), including
strict URL decoding and an explicit absent-body observation.

## What a binding proves

`request_context_bound: true` means the retained context names the exact response
digest and size and the projection binds both inputs. It does **not** authenticate
the collector's assertion that this request produced those results. A party that
can replace both inputs and sign a new case can construct a new consistent
assertion. Preserve independent acquisition/custody evidence and review the
original context against the investigation question.

`request_scope_verified`, `query_execution_verified`, and
`source_authenticity_verified` remain false. `context_source` is
`retained-assertion`. An absent result error leaves `collection_complete` unknown
(`null`); a valid `PartialError` keeps it false even when replay passes. Empty
results do not prove absence of activity, and result rows may be aggregates.

Microsoft documents workspace POST parameters in the JSON body, including
optional timespan and additional workspaces. A timespan in both the URL and body
has intersection semantics; this bounded profile rejects all URL query strings
instead of discarding them. See [request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format).
KQL itself can reference other resources and saved functions, so recorded endpoint
and workspace lists do not enumerate effective scope. See
[cross-resource queries](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cross-workspace-query).

## Explicit input profile

Use `--format workspace-post` with two separate UTF-8 JSON files:

1. The exact retained native `tables` response, within the existing
   [table profile](LOG_ANALYTICS_REPLAY_V1.7.md), including its numeric/type limits.
2. An AI-DFIR context record with exactly `schema`, `request`, and `response`.

The context schema is `ai-dfir/log-analytics-query-context/v1.7`.

| Object | Required fields | Optional fields / restrictions |
|---|---|---|
| `request` | `method`, `url`, `body`, `headers` | No other fields |
| `request.body` | `query` | `timespan`, `workspaces` only |
| `request.headers` | `content-type: application/json` | `prefer`, `x-ms-client-request-id` only |
| `response` | `status`, `body_sha256`, `body_size_bytes`, `headers` | No other fields |
| `response.headers` | None; explicit object required | `content-type`, `x-ms-request-id`, `request-id`, `x-request-id` only |

The method must be exact `POST`. The URL must be exactly
`https://api.loganalytics.io/v1/workspaces/{GUID}/query` or
`https://api.loganalytics.azure.com/v1/workspaces/{GUID}/query`, with a hyphenated
workspace GUID. URL query strings, fragments, credentials, explicit ports,
alternate paths, resource-context queries, batch, and sovereign endpoints
require another profile. GET uses the separate `workspace-get` profile above;
it is not inferred from a POST record. The URL is data, never fetched.

All header names in this record must use the lowercase keys above. Header values
must be nonempty strings without control characters. Authorization/cookie fields
and unknown fields fail; this is an explicit selected-header record, not a full
wire capture. Preserve additional relevant noncredential observations separately.
The profile does not detect secrets embedded in query text or otherwise guarantee
redaction of original evidence. Do not put bearer tokens in the context record.

`query` is a nonblank UTF-8 string up to 64 KiB; tabs, CR, and LF are preserved.
It is not parsed or syntax-checked. `timespan`, if present, is a nonblank string
up to 256 characters without controls. It is retained as an opaque observation,
not validated as an ISO duration or converted into absolute time. `workspaces`,
if present, is an array of at most 32 hyphenated GUID strings. Empty lists,
duplicates, order, and letter case are retained without deduplication. Nulls or
coerced values fail; missing optional fields remain absent.

`response.status` must be a JSON integer exactly 200. Microsoft documents that
this status can still carry usable partial results; the existing parser retains
that distinction. See [response format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format).
Unknown status, fatal responses, and other status codes are outside this profile.
`body_sha256` must equal lowercase SHA-256 of the exact response file, and
`body_size_bytes` must be an integer equal to its byte length. These checks run
before the table parser. Do not substitute a canonical JSON digest for the raw
file digest. Reserializing a collector's parsed JSON binds the reserialized
artifact, not the original HTTP wire body.

The legacy response-only Azure collector receipt does not automatically capture
KQL and all request context. The explicit
[automatic capture option](LOG_ANALYTICS_CAPTURE_V1.7.md) now preserves a compatible
context during bounded workspace POST acquisition, with a separate explicit
[GET capture choice](LOG_ANALYTICS_GET_CAPTURE_V1.7.md). Other acquisitions still need
separately retained observations; this replay tool never infers missing fields
from response columns, receipts, or filenames.

## Projection and commands

```bash
python log_analytics_context_v17.py --input retained-response.json \
  --context retained-query-context.json --format workspace-post \
  --out context-projection.json

python log_analytics_context_v17.py --input retained-response.json \
  --context retained-query-context.json --format workspace-post \
  --compare context-projection.json
```

The CLI only reads regular bounded files and creates output exclusively. It
preserves existing files and symlink targets. Creation or a matching comparison
exits 0, including correctly preserved partial results with explicit incomplete
state; invalid/mismatched/unavailable/conflicting input exits 1; malformed CLI
arguments exit 2. Error reports omit private input values and paths.

`source_sha256` and `context_sha256` bind exact input bytes, including whitespace.
`request_sha256` binds the canonical JSON request object. `binding_sha256` hashes
canonical JSON containing `profile`, `response_sha256`, and `context_sha256`.
The request projection hashes query text, URL, primary/additional workspace IDs,
body, optional scope observations, and selected headers. Those field digests use
RFC 8785 canonical JSON, including JSON string encoding. Query byte length is
reported separately. Ordered additional-workspace digests preserve duplicates.
The response projection retains status and byte size plus a selected-header
digest. `result` is the complete existing typed table projection.

No query text, timespan text, workspace IDs, or header values are copied into the
projection. Typed result scalars and table/column names retain the existing
content policy. Hashes and projections can still be sensitive. Original context
and response artifacts retain their full content and require access control.

## Signed-case integration

Bind response, context, and projection as **three distinct EvidenceArtifact
records**, each with its own case-relative path, exact content digest, and ledger
commitment. Add a `derived-from` relationship from response to projection with:

```json
{
  "transformation": "v17_log_analytics_context.normalize",
  "transformation_version": "1.7",
  "metadata": {
    "input_format": "workspace-post",
    "context_artifact_id": "QUERY-CONTEXT"
  }
}
```

`QUERY-CONTEXT` must identify the separately bound context artifact, not a path,
URL, arbitrary record, response, or projection. Known-profile metadata must have
exactly those two keys. Context is a second derivation input in lineage cycle
validation. Missing references, self-references, and cycles reject provenance
before reconstruction. Unknown transform versions stay unsupported and yield
INCOMPLETE when replay is requested.

Sign/export using the existing [investigation replay workflow](INVESTIGATION_REPLAY_V1.7.md).
Required trust/timestamp gates still run before reconstruction. Replay reads all
three verified artifacts from the same open archive without extraction. A signed
but incorrect projection or substituted context can retain integrity PASS while
replay FAIL produces requested-replay CLI exit 1. Matching replay only reproduces
the retained assertion; analyst review remains necessary.

## Bounds and acceptance

Context is limited to 128 KiB, request text to 64 KiB, each header value to 4,096
characters, and additional workspaces to 32. The response remains limited to
8 MiB with the existing table, row, cell, depth (32), and node (200,000) budgets.
Projection is limited to 8 MiB plus 128 KiB and independently checked for depth
and nodes. Strict JSON rejects duplicates, nonfinite numbers, invalid Unicode,
unsafe RFC 8785 integers, and trailing documents. No malformed record is skipped.

Run `python v17_log_analytics_context_selftest.py` and
`python -m pytest tests/test_v17_log_analytics_context.py -q`. Acceptance uses only
synthetic data and ephemeral signing keys, with network, process execution, and
archive extraction disabled during replay. Full source and extracted-package
gates require the self-test and all focused regressions; new-profile package
completeness/assurance checks remain conditional for historical releases.
