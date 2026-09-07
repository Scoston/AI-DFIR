# Google Cloud Logging acquisition context and offline replay

Development profile: `v17_gcp_logging_context.normalize@1.7`, format
`entries-list`. This is the tenth fixed replay adapter. It binds a separately
retained request-context artifact to the exact bytes of one Cloud Logging
response and the existing [Google Cloud Audit projection](GCP_AUDIT_REPLAY_V1.7.md).

Capture completion, signed package integrity, deterministic replay, provider
origin, effective scope, pagination coverage, and evidence conclusions remain
separate. A replay PASS does not prove that the recorded query ran, the named
resources were accessible, all matching entries were acquired, or a human
performed an observed action. Context is a retained assertion. The capture
receipt is unsigned until incorporated into an independently signed case.

## Request profile

The fixed endpoint is `POST https://logging.googleapis.com/v2/entries:list`.
The [Google entries.list reference](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)
defines its resources, filters, ordering, and continuation behavior. This local
profile is deliberately bounded and does not accept every provider option.

| Body field | Local acceptance | Projection |
| --- | --- | --- |
| `resourceNames` | Required array of 1–32 container or LogView names | Whole ordered array and individual name digests; duplicates retained |
| `filter` | Optional string, up to 20,000 characters; empty and multiline text allowed | Presence and digest; filter is not interpreted |
| `orderBy` | Optional `timestamp asc` or `timestamp desc` | Presence and digest; no default inserted |
| `pageSize` | Optional JSON integer from 1 to 1,000; Boolean/float/string rejected | Presence and digest |
| `pageToken` | Optional opaque string up to 4,096 characters; empty allowed | Presence and digest; previous-page relationship remains unverified |

Resource containers begin with `projects/`, `organizations/`, `folders/`, or
`billingAccounts/`, followed by one identifier. A complete optional suffix is
`/locations/{location}/buckets/{bucket}/views/{view}`. Identifiers are 1–256 ASCII
letters, digits, underscore, period, colon, or hyphen. Standalone `.`/`..`, extra
segments, encoded paths, whitespace, URL punctuation, and non-ASCII names are
rejected. This validates retained syntax, not resource existence or authority.

No deprecated `projectIds`, arbitrary endpoint, additional query-string options,
credential field, headers parameter, command, or pagination limit is accepted.
Absent and empty filter/token values remain distinct. Control characters are
rejected except tab, CR, and LF in filters. No query rewriting, time-window
inference, resource sorting, deduplication, or automatic defaulting occurs.

## Automatic capture

Use an operator-provided `GOOGLE_OAUTH_ACCESS_TOKEN` in the process environment.
Do not put credentials in parameters or command-line arguments. An example
parameter file contains the request body itself:

```json
{
  "resourceNames": ["projects/synthetic-source"],
  "filter": "logName:\"cloudaudit.googleapis.com\"",
  "orderBy": "timestamp desc",
  "pageSize": 1000
}
```

```bash
python provider_collectors_v15.py google_cloud_logs --capture-context \
  --params-file logging-params.json --out new-logging-capture
```

The parent directory must exist and be protected. The destination must be new.
The existing response-only collector remains available. Azure-specific capture
method, scope, and GET-encoding flags are rejected for Google Cloud capture.

The collector prepares canonical request JSON, records its method, fixed URL,
decoded body, and selected headers, and compares those observations with the
returned request. It performs one verified-TLS request with 10-second connect
and 45-second read timeouts. A direct HTTP adapter disables redirects, retries,
preloading, environment proxy/CA merging, ambient netrc/cookies, and content
decoding. It does not follow a continuation token. Only the operator can choose
to acquire another page with explicitly retained parameters.

The identity-encoded response body is read in bounded chunks, with an 8 MiB
maximum and exact Content-Length checking when present. Compression is rejected.
Bounded entity-body bytes are preserved before Audit Log parsing; this is not a
packet, TLS transcript, HTTP header transcript, or transport-origin attestation.

Only request `content-type: application/json` and response `content-type`,
`x-request-id`, and `x-goog-request-id` are retained as selected observations.
Header spelling is normalized to lowercase during capture. Header values are
bounded to 4,096 characters. Authorization and cookies are excluded. The configured
token cannot occur in the selected observations or retained request. Raw evidence
may itself contain sensitive content; the collector does not rewrite response
bytes or claim general secret detection.

## Artifact sets and status

A compatible HTTP 200 Audit Log response creates `response.json`, `context.json`,
`projection.json`, and the final `receipt.json`. The context binds response byte
size and SHA-256 before the native Audit Log parser runs. Directory and file
creation is exclusive, with POSIX modes 0700 and 0600. An exclusive link publishes
the receipt only after member writes finish. A partial write or interruption
cannot publish a successful receipt. Existing destinations and symlink outputs
are not overwritten. Operators retain and investigate partial directories.

| Observation | Capture status | Collection completeness |
| --- | --- | --- |
| Compatible page with nonempty continuation token, including empty entries | `CAPTURED` | `false` |
| Compatible page without a continuation token, including an empty page | `CAPTURED` | unknown (`null`) |
| Bounded non-200 response or recorded error envelope | `FAILED` | `false` |
| Bounded malformed, mixed, or unsupported response | `FAILED` | unknown unless an error was recorded |
| Transport, size, encoding, credential, or write failure | Error; no successful receipt | No complete claim |

An empty page can still represent an unfinished search. Absence of continuation
does not establish global coverage, retention, permissions, sink configuration,
or a complete prior pagination chain. Responses with non-Audit Log entries are
unsupported by this profile. A null `nextPageToken` is rejected by the existing
native parser; absent and empty string forms are supported.

Bounded unsupported responses produce `response.json` and a distinctly typed
`capture-observation.json`, plus a failed receipt. They never produce a compatible
context/projection claim. Receipt stdout contains digests, status, and counts,
not filters, resource names, pagination tokens, or payloads. CLI exits are 2 for
`CAPTURED` with incomplete/unknown collection, 1 for failure, and 130 for interruption.

## Offline context and signed replay

Manual context uses schema `ai-dfir/gcp-logging-query-context/v1.7`, exact keys
`schema`, `request`, and `response`, and the same fixed request profile. The
response has `status`, `headers`, `body_sha256`, and `body_size_bytes`. No network
access occurs when importing or comparing it:

```bash
python gcp_logging_context_v17.py --input capture/response.json \
  --context capture/context.json --format entries-list --out new-projection.json
python gcp_logging_context_v17.py --input capture/response.json \
  --context capture/context.json --format entries-list --compare capture/projection.json
```

Record response, context, and projection as three distinct signed case artifacts.
Use a `derived-from` relationship from response to projection with transformation
`v17_gcp_logging_context.normalize`, version `1.7`, and metadata:

```json
{"input_format":"entries-list","context_artifact_id":"QUERY-CONTEXT"}
```

The context identifier must reference a separate bound artifact. It participates
as a second input in lineage cycle checks. Signature/inventory/checkpoint gates
run before replay. Unknown versions remain unsupported and never load arbitrary
code. Replay compares the complete canonical projection, including exact source
and context hashes, request digests, selected header observations, and the native
Audit Log projection. Re-signing substituted content cannot turn an inconsistent
recorded projection into a matching replay.

Context and parameter documents are limited to 128 KiB. Native input remains
8 MiB, with existing 2,000-entry, 1 MiB entry, depth-32, 200,000-node, strict JSON,
numeric, and metadata limits. Combined output is at most 8 MiB plus 128 KiB and
is structure-checked again. No entries are skipped to manufacture success.
The offline CLI requires bounded regular-file inputs and creates output exclusively.

## Acceptance

`v17_gcp_logging_capture_selftest.py` uses only synthetic responses and transport.
The 228 regressions cover signed offline replay and substitutions, empty-page
continuation, resource/filter/ordering/token distinctions, strict bounds, unsafe
transport and headers, redirects, stream failure, credential contamination,
exclusive outputs, interruption, CLI behavior, unverified archives, and lineage
cycles. Existing native Audit Log and Azure profiles remain covered separately.
The release gate and extracted-package assurance require this self-test and the
full regression count. Live permissions, service availability, and production
acquisition have not been qualified by synthetic acceptance.
