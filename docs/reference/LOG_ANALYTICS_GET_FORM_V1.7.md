# Form-encoded Log Analytics GET and workspace lists (unreleased)

Explicit `workspace-get-form` and `resource-get-form` profiles add bounded form
decoding to the existing context adapter, with automatic capture through
`--capture-get-encoding form`. The workspace profile also accepts an optional
comma-separated list of additional workspace GUIDs. The original percent-only
GET profiles and their artifact digests remain unchanged.

## Provider format and evidence limits

Microsoft documents a GET `workspaces` parameter containing comma-separated
identifiers and examples using literal `+` for spaces in
[Cross workspace queries](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/cross-workspace-queries).
This implementation accepts only GUID identifiers and at most 32 additional
workspaces, a smaller profile than the provider's full API. Resource-context GET
does not accept this extra scope parameter.

The decoding order follows the [form parser's plus and percent rules](https://url.spec.whatwg.org/#concept-urlencoded-parser):
literal plus becomes space before one UTF-8 percent decode. This profile is
stricter than the general parser: missing equals signs, empty fields, duplicates,
unsupported names, invalid percent escapes and invalid UTF-8 all fail closed.
No tolerant repair, Unicode normalization, second decoding, or automatic profile
selection occurs.

| Retained query component | Decoded observation |
|---|---|
| `a+b` | `a b` |
| `a%20b` | `a b` |
| `a%2Bb` | `a+b` |
| `a%252Bb` | `a%2Bb` |

Matching replay only demonstrates reproducibility of retained assertions and
exact response bytes. A requested workspace list does not prove effective query
scope, access rights, provider origin, execution, or collection completeness.
KQL and saved functions can reference other data sources. Duplicate workspace
IDs, their order, spelling, and case remain evidence observations; the projection
does not claim they represent distinct sources. Empty/error-free results remain
unknown, and PartialError remains incomplete.

## Bounded context profile

The context schema, HTTP/header allowlists, absent GET body, exact response
digest/size checks, table semantics, and 128 KiB context/96 KiB URL/64 KiB decoded
query budgets are inherited from the [GET profile](LOG_ANALYTICS_GET_CONTEXT_V1.7.md).
Resource paths and opaque permission observations follow the
[resource profile](LOG_ANALYTICS_RESOURCE_V1.7.md).

After splitting on literal `&` and the first `=`, each component must contain
only ASCII letters/digits, `._~*()+,-`, or complete percent escapes. Reserved
characters outside this set must be percent encoded. Literal spaces, non-ASCII
URL characters, controls, slashes, backslashes, fragments, and malformed escapes
are rejected. Decoded query text may contain tab/CR/LF within the existing query
rules; decoded timespan stays bounded opaque text.

`query` is required, `timespan` optional. `workspace-get-form` alone also allows
one `workspaces` field. Its decoded value must contain 1–32 complete GUIDs
separated by single commas, with no whitespace, empty elements, friendly names,
resource IDs, or nested encoding. Percent-encoded aliases of duplicate parameter
names are duplicates and are rejected.

The projection binds the original full URL, query string and order separately
from decoded parameters. Equivalent decoded values do not erase differences in
encoding or spelling. `url_decoding` is `utf8-form-plus-then-percent-once`.
Workspace projections additionally record the absent/present CSV digest and
ordered `additional_workspace_sha256` list. The profile itself participates in
the binding digest, including when a URL needs no decoding.

## Explicit capture

Use an operator-owned JSON file with `workspace_id`, `kql`, optional `timespan`,
`workspaces` as a JSON array of GUID strings, `prefer`, and `client_request_id`.
For resource scope, use `resource_id` and omit `workspaces`.

```bash
python provider_collectors_v15.py azure_foundry_logs --capture-context \
  --capture-method GET --capture-get-encoding form \
  --params-file workspace-params.json --out new-form-capture
```

Add `--capture-scope resource` for resource GET. The Python API accepts
`capture(params_raw, out_dir, method="GET", scope="workspace", get_encoding="form")`.
The default encoding is `percent`; form is rejected for POST. The CLI encoding
flag requires both capture mode and an explicit GET method.

The collector encodes decoded operator values once, uses `+` for spaces and
`%2B` for literal plus, and percent encodes the joined workspace CSV. Each array
element is validated independently so an element cannot inject another workspace
through a comma. Arbitrary URLs and implicit scope changes remain unsupported.

Actual prepared/observed requests must match. Configured credentials are checked
in decoded values as well as retained request/header observations. The shared
transport still verifies TLS and makes one request with bounded undecoded reads,
no retries, redirects, proxy/session/environment credential merge, or fallback
to POST/another encoding. Private exclusive artifact creation and final receipt
publication are unchanged. Receipts identify the explicit form input format;
CAPTURED retains exit 2, failed acquisition exit 1, interruption 130. Original
context and request logs remain sensitive evidence.

## Offline replay and acceptance

```bash
python log_analytics_context_v17.py --input response.json --context context.json \
  --format workspace-get-form --out new-projection.json
python log_analytics_context_v17.py --input response.json --context context.json \
  --format workspace-get-form --compare new-projection.json
```

Signed lineage uses the existing context transformation/version and separate
context artifact reference with the new explicit input format. Resource form
uses `resource-get-form`. Offline replay never executes a query.

The synthetic form self-test covers workspace/resource capture and signed replay,
partial results, and plus/space substitution. The 123 focused regressions cover
encoding order and UTF-8, malformed/duplicate parameters, URL/query budgets,
workspace lists and scope injection, equivalent URL spelling, re-signed
substitutions, configured credentials, failure behavior and CLI capture/replay.
Existing GET/resource capture tests continue to enforce compatibility and
protected transport/output behavior. Full source and extracted-package gates
require the self-test and regressions. Conditional package/assurance requirements
preserve historical release verification; no new dependencies or live provider
acceptance are used.
