# Automatic Log Analytics workspace GET capture

Explicit [form GET capture](LOG_ANALYTICS_GET_FORM_V1.7.md) adds
`--capture-get-encoding form` and bounded additional workspace GUID lists. Default
percent-only GET capture below retains its existing parameters and artifacts.

This unreleased acquisition option produces the three artifacts needed for
[workspace GET context replay](LOG_ANALYTICS_GET_CONTEXT_V1.7.md): the exact
retained response body, the prepared GET request context, and its deterministic
projection. The operator no longer needs to assemble the GET context afterward.
It extends the existing [capture implementation](LOG_ANALYTICS_CAPTURE_V1.7.md)
with an explicit method choice. POST remains the default and retains its reviewed
context, projection, and receipt digests.

Microsoft documents GET queries with parameters in the URL; see
[request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format).
This option implements only the reviewed public workspace query/timespan profile.
It is not a general HTTP client or an automatic fallback for other acquisition
methods. Offline replay never invokes this acquisition path.

## Explicit invocation

Prepare a protected UTF-8 JSON parameter file. This example uses a synthetic
workspace ID; substitute the authorized workspace and query for an actual
acquisition:

```json
{
  "workspace_id": "00000000-0000-0000-0000-000000000001",
  "kql": "AzureActivity | summarize count()",
  "timespan": "PT12H",
  "prefer": "wait=30",
  "client_request_id": "operator-selected-request-id"
}
```

Provision `AZURE_LOG_ANALYTICS_TOKEN` through the approved secret-handling process,
then invoke the collector explicitly:

```bash
python provider_collectors_v15.py azure_foundry_logs \
  --capture-context --capture-method GET \
  --params-file get-parameters.json --out get-capture-001
```

`--out` must be a new directory with an existing protected parent. The method
option requires `--capture-context`; it accepts exact `POST` or `GET`. Omitting
it keeps POST. No capture method changes the legacy response-only collector.
Only `azure_foundry_logs` supports context capture. The existing `--params-json`
alternative remains available, but exposes supplied query text to command-line
history and process inspection. A parameter file and nondefault JSON argument
cannot be combined. Parameter files must be regular bounded files.

The Python API is:

```python
receipt = v17_log_analytics_capture.capture(params_raw, output_directory, method="GET")
```

There is no method field in parameter JSON. Required fields are `workspace_id`
and `kql`; optional fields are exactly `timespan`, `prefer`, and
`client_request_id`. GET rejects `workspaces`, including an empty list or null,
rather than silently removing a recorded scope choice. Raw URLs, bodies,
arbitrary headers, credentials, and additional parameters are also rejected.

## Request construction and credential handling

The collector constructs one GET to
`https://api.loganalytics.io/v1/workspaces/{GUID}/query`. The query string contains
`query` followed by optional `timespan`. Inputs are decoded strings, not
pre-encoded URL fragments. UTF-8 percent encoding happens once: spaces become
`%20`, literal plus becomes `%2B`, and an input literal `%20` becomes `%2520`.
Reserved characters inside values remain data; they cannot introduce another
parameter. Query text and timespan remain opaque observations, without local KQL
execution or time-range interpretation.

The generated URL must pass the existing strict GET replay profile. It is limited
to 96 KiB after encoding, with decoded query text limited to 64 KiB, timespan to
256 characters, and parameter input to 128 KiB. Optional header values are bounded
by the existing 4,096-character limit. The complete context must fit the existing
128 KiB replay budget. These are local parser limits, not provider request-length
guarantees. A provider rejection such as HTTP 414 is preserved as a failure;
there is no POST fallback or automatic retry.

The actual Requests prepared method, URL, absent body, and selected headers must
match the constructed request before output creation or acquisition. The returned
request observation must match that snapshot too. Context records `method: GET`,
the exact prepared URL, and `body: null`; it never substitutes a synthetic JSON
body for a GET request. Selected request headers are `accept: application/json`
plus supplied `prefer` and `x-ms-client-request-id`. Authorization is used for
transport and omitted from the retained context.

The configured bearer token is checked against decoded query/timespan values as
well as retained request and selected-header observations. Tokens containing
`+`, `/`, or `=` cannot evade that check through percent encoding. This detects
that configured value, not every possible secret. GET puts the query in the URL;
original context and any independently retained request logs require appropriate
access control. Routine receipt/error output omits query text, URLs, credentials,
header values, and output paths.

## Retention, transport, and failure behavior

GET uses the existing bounded direct HTTP-adapter path: verified TLS, no ambient
proxy/CA/netrc/session credentials, no redirects/retries/preloading/content
decoding, a 10-second connect timeout, and a 45-second read-inactivity timeout.
It requires direct connectivity through the normal CA trust store. There is no
hard overall execution deadline. Response reads are bounded to 8 MiB in chunks
of at most 64 KiB, with Content-Length and content-encoding checks. Exact retained
entity-body bytes are written before JSON parsing. This does not capture TLS
records, HTTP framing, or raw header bytes.

Artifact names, response-header distinctions, exclusive private creation,
fsync/exclusive receipt publication, interruption handling, and signed-case trust
boundaries follow the [shared capture guide](LOG_ANALYTICS_CAPTURE_V1.7.md).
GET receipts that are published add `request_method: GET` and
`input_format: workspace-get` to the existing receipt schema. Default/explicit
POST receipts retain their previous shape.

| Outcome | Retained files / CLI behavior |
|---|---|
| Supported HTTP 200, including valid PartialError | Response/context/projection and receipt; `CAPTURED`; exit 2 because collection is unknown/incomplete |
| Bounded unsupported result, excessive context, HTTP failure, or redirect | Response, separate `capture-observation.json`, and failed receipt; exit 1; no valid context/projection claim |
| Invalid parameters/credentials, conflicting output, unsafe response headers, encoding/length/stream failure | Redacted failure; exit 1; no completed artifact-set claim |
| Interruption | Existing partial files remain; `INTERRUPTED`; exit 130 |
| Invalid method option or method option without capture mode | Argument error; exit 2; no acquisition |

The shared receipt rules keep PartialError and non-200 responses incomplete.
Error-free and empty supported responses leave collection completeness unknown.
Acquisition completion is separate from collection completeness and provider
execution/scope/origin verification. Those verification claims remain false.
The receipt is unsigned until separately retained within a signed case.

## Signed replay and acceptance

Bind `response.json`, `context.json`, and `projection.json` as three distinct
ledger-committed EvidenceArtifacts. Use the existing
`v17_log_analytics_context.normalize` transformation, version `1.7`, with metadata
`input_format: workspace-get` and a separate `context_artifact_id` reference.
Follow the [GET context signed-case instructions](LOG_ANALYTICS_GET_CONTEXT_V1.7.md).
Preserve the receipt separately as acquisition evidence. Offline replay reads
only retained signed artifacts; it never performs another query. A substituted
query, workspace, timespan, encoding, request ID, or response can retain integrity
PASS in a reissued signed case while replay fails.

```bash
python v17_log_analytics_get_capture_selftest.py
python -m pytest tests/test_v17_log_analytics_get_capture.py -q
```

The 143 focused regressions use synthetic responses, credentials, and signing
keys. They cover automatic signed offline replay, encoded credential omission,
URL/decoded-query bounds, prepared/observed request comparison, the real HTTP
adapter's GET controls, response/failure retention, protected output and
interruption, CLI contracts, and unchanged reviewed POST artifact digests.
Source and extracted-package gates require the self-test and all regressions;
conditional package completeness/assurance preserves historical release
verification. No live provider acquisition is used for acceptance.
