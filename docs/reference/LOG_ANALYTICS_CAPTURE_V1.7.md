# Automatic Log Analytics acquisition-context capture

This unreleased option closes the manual preservation gap in
[retained query-context replay](LOG_ANALYTICS_CONTEXT_V1.7.md). An explicitly
invoked workspace POST acquisition records the prepared request, preserves the
bounded response body before parsing, and writes compatible context and
projection artifacts. It does not run during offline verification or replay.

This acquisition option remains workspace POST. Separately retained GET requests
can use the [offline GET context profile](LOG_ANALYTICS_GET_CONTEXT_V1.7.md);
that profile does not add GET acquisition to this collector.

## Explicit invocation

Use the existing provider collector CLI with `--capture-context`. For this mode,
`--out` is a **new directory**, and its parent must already exist. Use an
operator-controlled parent directory with appropriate access controls.

Prepare a protected UTF-8 JSON parameter file, for example:

```json
{
  "workspace_id": "00000000-0000-0000-0000-000000000001",
  "kql": "AzureActivity | summarize count()",
  "timespan": "PT12H",
  "workspaces": [],
  "prefer": "wait=30",
  "client_request_id": "operator-selected-request-id"
}
```

The workspace above is synthetic; supply your authorized workspace and query.
Only `workspace_id` and `kql` are required. Optional fields are exactly
`timespan`, `workspaces`, `prefer`, and `client_request_id`. Their values are
validated against the existing bounded workspace POST context profile; absent
fields remain absent. KQL and timespan observations are not interpreted locally.
Microsoft describes workspace POST body parameters in its
[request-format documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format).

Provision `AZURE_LOG_ANALYTICS_TOKEN` through your approved secret-handling
process. The capture profile reads this fixed environment variable; it does not
accept token fields in parameter JSON or obtain credentials from netrc.

```bash
python provider_collectors_v15.py azure_foundry_logs \
  --capture-context --params-file capture-parameters.json --out capture-001
```

Capture mode also accepts the existing `--params-json` argument, but query text
on a command line can appear in shell history and process inspection. The file
option avoids that exposure. Do not combine a parameter file with nondefault
`--params-json`. `--params-file` requires capture mode. Capture mode is supported
only for `azure_foundry_logs`; other providers fail before acquisition.

The legacy command without `--capture-context` retains its original output-file,
receipt, and exit behavior. The `azure_foundry_logs()` response-only Python API
is unchanged. The capture API is
`v17_log_analytics_capture.capture(params_raw: bytes, out_dir)`.

## Acquisition and byte semantics

The capture path makes one explicit POST to
`https://api.loganalytics.io/v1/workspaces/{GUID}/query`. It builds and records the
prepared method, URL, JSON body, and selected noncredential headers. The returned
request observation must agree with that record. No source field can choose a
host, path, HTTP method, proxy, TLS override, or arbitrary command.

The transport uses the existing Requests dependency's HTTP adapter directly with
TLS certificate/hostname verification, no retries, no redirects, no response
preloading, and no content decoding. It does not merge environment proxies or CA
overrides, netrc, or session cookies. This bounded profile therefore requires
direct provider connectivity through its normal CA trust store. Requests exposes
prepared request observations and undecoded response streams; see
[Requests advanced usage](https://requests.readthedocs.io/en/latest/user/advanced/).

`response.json` contains the exact bytes read from the response entity body,
before JSON parsing or reserialization. TLS records, HTTP framing/chunks, and
original raw header bytes are **not** captured. The request's selected JSON body
is retained semantically in context; this is not a packet or full wire capture.
`Accept-Encoding: identity` is requested; compressed responses are rejected
instead of implicitly decompressed. Reads request at most 64 KiB at a time and
stop at the 8 MiB body limit. Declared Content-Length is validated against the
limit and actual retained length; it cannot bypass the read bound.

Connect timeout is 10 seconds and read-inactivity timeout is 45 seconds. These
are not a hard overall wall-clock deadline; operators must supervise processes
when an overall execution deadline is required.

Response header observations retain their actual selected names independently:
`content-type`, `x-ms-request-id`, `request-id`, and `x-request-id`. The capture
does not merge different request-ID fields or relabel one as another. Header
names use the context profile's lowercase representation, not original wire
casing. Repeated values of the same HTTP header follow the HTTP library's header
representation. Other response headers are excluded.

## Artifacts and result states

| Outcome | Retained files | Receipt / CLI exit |
|---|---|---|
| Supported HTTP 200 result, including valid PartialError | `response.json`, `context.json`, `projection.json`, `receipt.json` | `CAPTURED`, artifact set complete; exit 2 because collection is unknown/incomplete |
| Bounded body with unsupported HTTP status, JSON, or replay profile | `response.json`, `capture-observation.json`, `receipt.json` | `FAILED`, artifact set incomplete; exit 1 |
| Configuration/credential/output conflict, unsafe headers, compression/length/stream failure | No complete artifact set; an output directory may remain | Redacted failure; exit 1 |
| Interrupted acquisition/write | Any partial files already written remain | `INTERRUPTED`, no complete claim; exit 130 |

`capture-observation.json` uses the explicitly different schema
`ai-dfir/log-analytics-capture-observation/v1.7`. It can retain a failed request's
selected observations and exact response binding, but is not a compatible replay
context and never comes with a successful projection claim. Empty or malformed
bodies remain exact bytes in `response.json` even when they are not valid JSON.
Failures before a bounded body is obtained do not claim body preservation.

`receipt.json` uses `ai-dfir/log-analytics-capture-receipt/v1.7` and contains only
fixed artifact names, their exact digests/lengths, status, and interpretation
flags. It does not include query text, workspace IDs, selected header values, or
operator output paths. A successful artifact set does not establish complete
collection: no result error leaves completeness unknown, and PartialError keeps
it false. A non-200 response or a parsed response containing an error also keeps
completeness false; other unsupported responses leave it unknown. The receipt
reports an observed error separately from replay-profile support.

Existing files and symlink targets are never overwritten. The collector reserves
the directory before network activity and creates each member exclusively. On
POSIX, the directory starts with mode 0700 and members with mode 0600. On systems
where those modes do not establish private ACLs, protect the parent ACL first.
Members are flushed and fsynced before the final receipt is published by an
exclusive hard link from `receipt.pending.json`. The filesystem must support
hard links. Failures before publication leave no successful final receipt. If
interrupted after publication, validate the final receipt against member digests
before treating the set as complete. A leftover pending copy is not a completion
marker. Publication does not certify filesystem power-loss durability; validate
retained file digests after recovery. Failed capture directories are retained.

## Content and trust boundaries

Only selected noncredential headers enter context. Authorization, cookies, and
credential parameter fields are excluded or rejected. The configured bearer
value is checked for contamination in retained request/selected-header fields.
This is not a general secret classifier: queries and raw provider evidence may
contain other sensitive material and remain protected evidence. Producing a
digest-only receipt or projection does not redact the original artifacts.

`network_attempted` records the collector's transport call. Neither it nor TLS
verification independently proves what a compromised collector or provider did.
`query_execution_verified`, `request_scope_verified`, and
`source_authenticity_verified` remain false. Effective scope can depend on KQL,
saved functions, permissions, configuration, and retention. Operator authorization,
independent acquisition/custody evidence, and analyst judgment remain necessary.

The receipt is unsigned. Bind the response, context, and projection as three
separate EvidenceArtifact records and ledger commitments, then use the existing
signed export and context relationship described in
[context replay](LOG_ANALYTICS_CONTEXT_V1.7.md). Preserve the receipt separately
as acquisition evidence. Offline verification uses the same fixed adapter and
never performs acquisition. A substituted query/context/request ID or response
can retain valid signatures in a reissued case while replay fails.

## Acceptance and remaining scope

```bash
python v17_log_analytics_capture_selftest.py
python -m pytest tests/test_v17_log_analytics_capture.py -q
```

Acceptance uses synthetic responses and an ephemeral credential marker with
network/DNS disabled; no live provider access is required. It covers automatic
three-artifact signed-case replay, distinct header bindings, exact body bytes,
partial/error/empty responses, actual adapter redirect/preload controls, privacy,
size bounds, protected output paths, interruptions, and legacy compatibility.
Source and extracted-package release gates require the self-test and all 114
focused regressions. Wider numeric types, additional provider capture profiles,
resource/GET queries, proxy/custom-CA profiles, and scheduled acquisition remain
future work.
