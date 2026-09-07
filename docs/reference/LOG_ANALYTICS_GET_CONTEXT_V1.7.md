# Log Analytics retained workspace GET context

This unreleased profile adds `workspace-get` to the existing
[context replay adapter](LOG_ANALYTICS_CONTEXT_V1.7.md). It binds a separately
retained GET request URL, its decoded query and optional timespan, selected HTTP
observations, and exact response bytes. Signed-case replay detects substitution
without contacting Azure or executing KQL. Existing workspace POST projections
keep their original fields and digests.

Microsoft documents GET query text and an optional timespan in the URL.
See [Query - Get](https://learn.microsoft.com/en-us/rest/api/logsquery/query/get?view=rest-logsquery-v1)
and [request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format).
The rules below are a deliberately bounded AI-DFIR evidence profile, not a claim
to accept every URL or response supported by Azure.

## Required evidence

Retain the native response file and a separate UTF-8 JSON context file with schema
`ai-dfir/log-analytics-query-context/v1.7`. The outer record has exactly `schema`,
`request`, and `response`. The response fields and typed result restrictions are
the same as the existing [POST context profile](LOG_ANALYTICS_CONTEXT_V1.7.md):
integer HTTP 200, exact lowercase raw-file SHA-256 and byte length, and an explicit
selected-header object. PartialError stays incomplete; error-free and empty
responses leave collection completeness unknown. Wider integers, decimal columns,
coerced scalar strings, fatal responses, and unimplemented result types still fail.

The request has exactly these fields:

| Field | GET profile requirement |
|---|---|
| `method` | Exact string `GET` |
| `url` | Exact retained ASCII URL, including its encoded query string |
| `body` | Explicit JSON `null`, recording that there was no request body |
| `headers` | Explicit object; optional lowercase `accept`, `content-type`, `prefer`, `x-ms-client-request-id` only |

Missing body observations, empty strings, empty objects, and actual GET bodies
are not interchangeable with `null`. The tool does not reconstruct a body or
accept a second `params` object. GET headers are optional observations; an observed
content type does not infer a body or need to be `application/json`. Header values
remain nonblank strings of at most 4,096 characters without controls. Credential
and cookie headers are rejected. Response headers remain limited to `content-type`,
`x-ms-request-id`, `request-id`, and `x-request-id` as separate keys.

The base URL must be exactly one of:

- `https://api.loganalytics.io/v1/workspaces/{GUID}/query`
- `https://api.loganalytics.azure.com/v1/workspaces/{GUID}/query`

The workspace uses a hyphenated GUID; letter case is retained. The URL must then
contain `?` and the supported query string. Credentials, explicit ports, alternate
host spellings, path normalization, fragments, resource-context paths, batch, and
sovereign endpoints are outside this profile. The URL is data and is never fetched.

## Strict query-string interpretation

Exactly one `query` parameter is required and one `timespan` is optional, in either
order. Names are case sensitive after decoding. Every parameter has an `=`; the
only separator is `&`. Duplicate names fail even when encoded differently or when
their values match. Extra parameters, including `workspaces`, `api-version`, and
credential parameters, fail. Other GET parameters need a separately specified
profile; their omission must never be inferred from result columns.

Each encoded name and value may contain only ASCII unreserved characters
(`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) and valid `%HH` escapes. See the
[RFC 3986 unreserved character definition](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3).
Percent decoding happens exactly once and must produce valid UTF-8. This profile
requires reserved characters inside values to be percent encoded as well.

| Retained component | Profile interpretation |
|---|---|
| `%20` | Space |
| `%2B` | Literal plus |
| Raw `+` or space | Rejected; no form-decoding assumption |
| `%26timespan%3DPT1H` inside a value | Part of that value; never a new parameter |
| `%2520` | Literal `%20`; no second decode |
| `%71uery` | Decoded parameter name `query`; duplicate checks still apply |
| `%2f` and `%2F` | Same decoded slash, different retained URLs and context bindings |
| Raw `/`, `=`, `;`, `?`, or `#` inside a value | Rejected; require an encoded value |
| Malformed escapes or invalid UTF-8 | Rejected without replacement characters |

Decoded query text is nonblank and at most 64 KiB in UTF-8. Tabs, CR, and LF are
preserved; other C0 controls and DEL fail. No Unicode normalization, KQL parsing,
syntax validation, or execution occurs. Timespan is a nonblank opaque string of
at most 256 characters without controls. It is not resolved against the current
clock or treated as a validated absolute interval. For example, a recorded
start/end value encodes its slash as `%2F` in this profile.

Preserve the URL actually observed. Do not repair or re-encode an unsupported
retained URL to make it pass: that would be a different context assertion and
would require separately documented derivation. The 96 KiB URL limit and 128 KiB
whole-context limit both apply, including percent expansion and header observations.
These are parser budgets, not claims about a provider's accepted request length.

## Projection and commands

```bash
python log_analytics_context_v17.py --input retained-response.json \
  --context retained-get-context.json --format workspace-get \
  --out get-context-projection.json

python log_analytics_context_v17.py --input retained-response.json \
  --context retained-get-context.json --format workspace-get \
  --compare get-context-projection.json
```

Use the existing context record structure with a request such as this synthetic
example. Its response digest and size must come from the exact retained response;
this request fragment alone is not a complete context artifact.

```json
{
  "method": "GET",
  "url": "https://api.loganalytics.io/v1/workspaces/00000000-0000-0000-0000-000000000001/query?query=AzureActivity%20%7C%20take%201&timespan=PT12H",
  "body": null,
  "headers": {"accept": "application/json"}
}
```

The projection uses the existing context schema and transformation version with
`input_format: workspace-get`. It binds exact context and response bytes, the
canonical full request, and the complete existing typed result projection.
The GET request projection contains:

- `method`, `endpoint_host`, base `endpoint_sha256`, complete `url_sha256`, and `url_size_bytes`;
- `primary_workspace_sha256`, `body_state: absent`, and the canonical JSON null `body_sha256`;
- encoded `query_string_sha256`, decoded `parameters_sha256`, and decoded `parameter_order`;
- decoded `query_sha256`, UTF-8 `query_size_bytes`, optional `timespan` state/digest, and `headers_sha256`;
- fixed decoding identifier `url_decoding: utf8-percent-once-unreserved`.

Field hashes use RFC 8785 canonical JSON, including string encoding; source and
context hashes use exact file bytes. Canonical parameter hashing does not retain
map insertion order, so the explicit order and exact URL/context binding retain
that distinction. A changed escape spelling or parameter order causes replay
FAIL even when decoded parameter hashes match. Only projection whitespace is
ignored during comparison. Original query/URL/timespan/header values are omitted
from the projection and routine CLI output. Typed result scalars and table/column
names still follow the result profile's content policy. Original evidence and
digests can be sensitive; this is not a general secret classifier.

The CLI reads regular bounded files and creates output exclusively, preserving
existing files and symlink targets. Creation or matching replay exits 0, including
matching partial results with explicit incomplete state. Invalid, unsupported,
unavailable, conflicting, or mismatched inputs exit 1; malformed CLI arguments
exit 2. Error summaries omit input values and paths.

## Signed cases and interpretation

Bind the response, context, and projection as three distinct ledger-committed
EvidenceArtifacts. The response-to-projection `derived-from` relationship uses
the existing fixed adapter with the new explicit input profile:

```json
{
  "transformation": "v17_log_analytics_context.normalize",
  "transformation_version": "1.7",
  "metadata": {
    "input_format": "workspace-get",
    "context_artifact_id": "QUERY-CONTEXT"
  }
}
```

The context reference is validated as a second lineage input, including missing
references, self-reference, and cycles. Trust and archive-integrity gates precede
replay. The verifier reads all three artifacts from the same verified open archive
without extraction. Unknown transform versions remain INCOMPLETE. A signed but
substituted context or incorrect projection can yield integrity PASS and replay
FAIL; requested replay then exits 1. Follow the existing
[signed investigation replay workflow](INVESTIGATION_REPLAY_V1.7.md).

Replay PASS establishes a reproducible binding of retained assertions. It does
not prove that the provider received or interpreted that URL, that those results
came from its execution, that effective scope was complete, or that a human actor
was authenticated. `context_source` stays `retained-assertion`;
`query_execution_verified`, `request_scope_verified`, and
`source_authenticity_verified` stay false. KQL can name additional resources or
functions; absence of a workspace parameter does not establish effective scope.
The [automatic collector capture](LOG_ANALYTICS_CAPTURE_V1.7.md) defaults to POST
and now offers a separate [explicit GET option](LOG_ANALYTICS_GET_CAPTURE_V1.7.md).
This offline replay feature never invokes acquisition.

## Acceptance

Run `python v17_log_analytics_get_selftest.py` and
`python -m pytest tests/test_v17_log_analytics_get.py -q`. The 160 regressions cover
signed offline replay, URL and context substitution, encoding ambiguity and
injection, exact byte budgets, retained partial/unknown states, lineage, protected
CLI output, and unchanged reviewed POST projection digests. Acceptance uses
synthetic data and ephemeral signing keys. Source and extracted-package gates
require the self-test and all regressions; conditional package completeness and
assurance checks preserve historical v1.7.0 verification.
