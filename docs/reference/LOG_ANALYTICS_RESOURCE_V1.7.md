# Resource-scoped Log Analytics context and capture (unreleased)

The additional [resource form GET profile](LOG_ANALYTICS_GET_FORM_V1.7.md) supports
explicit plus/percent decoding. It retains the resource identifier and permission
boundaries below and does not accept additional workspaces.

The `resource-post` and `resource-get` profiles bind a retained Azure resource
query to exact response bytes and support automatic context capture. They use
the existing version 1.7 context replay adapter and separate signed response,
context, and projection artifacts. Existing workspace POST/GET projections and
capture artifact digests remain unchanged.

## Evidence and interpretation

The recorded resource identifier, query, timespan, and selected HTTP headers are
digest-bound. Neither recording nor matching replay establishes actual execution,
provider origin, authorization, effective source scope, or collection completeness.
Resource-context HTTP 200 results can silently omit sources the caller cannot
access; an empty or error-free result therefore remains unknown. PartialError
remains incomplete. KQL is never executed during replay.

Microsoft documents the direct resource endpoint and optional permissions
observation in [Querying logs for Azure resources](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/azure-resource-queries).
The separate [access-mode documentation](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access)
describes how resource and workspace permissions affect available data.

## Retained request profile

Both fixed public hosts, `api.loganalytics.azure.com` and `api.loganalytics.io`,
are accepted, with this exact path structure:

```text
https://api.loganalytics.azure.com/v1/subscriptions/<GUID>/resourceGroups/<group>/providers/<namespace>/<type>/<name>/query
```

This is a deliberately bounded identifier profile: ASCII unreserved characters
only in group/type/name segments; each segment has 1–256 characters; no segment
is `.` or `..`. The provider namespace has dot-separated nonempty ASCII
letter/digit/underscore/hyphen components and at most 256 characters. One through
eight type/name pairs are accepted for child resources. The resource ID is at
most 4,096 bytes. GUID spelling and every path segment's case are preserved.
Literal keywords such as `resourceGroups` have the displayed spelling.

Percent-encoded path segments, spaces, Unicode names, ports, credentials,
fragments, query-bearing POST URLs, ARM management endpoints, sovereign hosts,
subscription-only/group-only targets, and other path forms are unsupported.
This grammar is an acceptance boundary, not validation that a resource exists
or that Azure accepts every allowed name.

POST requires a JSON body with `query`, optional opaque `timespan`, and recorded
`content-type: application/json`. GET requires an explicit null body and the
existing strict once-only UTF-8 percent-encoded `query`/optional `timespan` URL
profile. Additional workspaces/resources and arbitrary extra parameters are
rejected. See [GET context](LOG_ANALYTICS_GET_CONTEXT_V1.7.md) for decoding,
query/URL budgets, duplicate rejection, and exact URL spelling/order binding.

The context schema, 128 KiB document budget, 64 KiB query budget, selected header
allowlists, HTTP 200 requirement, and exact response digest/size checks are shared
with [workspace context](LOG_ANALYTICS_CONTEXT_V1.7.md). Request summaries replace
the workspace digest with `resource_id_sha256`, its byte length, and
`requested_scope: resource`; original resource identifiers and queries stay in
the retained context and are omitted from routine summaries.

## Permission observations and typed results

`resource-tables` is an explicit additional input format in
`v17_log_analytics.normalize` and `log_analytics_v17.py`. It preserves the ordinary
typed table profile and allows an optional `permissions` JSON object. The object
is opaque and subject to the same strict JSON, numeric, depth/node and byte
budgets as the full response. Unknown object members are hash-bound without
being interpreted. Non-object/null permission values are rejected. The
`response_digests.permissions` observation distinguishes absent from present;
`permissions_verified` is always false. The original `tables` format continues
to reject this extra envelope field.

Resource context replay uses `resource-tables`. A permission claim is not an
authenticated RBAC decision or a complete inventory of queried sources. Exact
source bytes and the canonical permission observation are bound independently;
changing permissions and re-signing the case still fails replay against the old
projection. Existing [Evidence Pack conclusion gates](EVIDENCE_PACK_REPLAY_V1.7.md)
and collection-health requirements remain applicable; this adds no automatic
quality upgrade or analyst conclusion.

## Explicit capture

Prepare an operator-owned parameters file, using synthetic values here:

```json
{
  "resource_id": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/synthetic-rg/providers/Microsoft.Compute/virtualMachines/synthetic-vm",
  "kql": "AzureActivity | count",
  "timespan": "PT1H",
  "prefer": "include-permissions=true"
}
```

With the existing `AZURE_LOG_ANALYTICS_TOKEN` environment credential configured
through the operator's credential process:

```bash
python provider_collectors_v15.py azure_foundry_logs --capture-context \
  --capture-scope resource --capture-method POST \
  --params-file resource-params.json --out new-resource-capture
```

Use `--capture-method GET` for GET. The Python API is
`capture(params_raw, out_dir, scope="resource", method="POST")`. Scope defaults
to workspace and method to POST; resource selection is never inferred from
parameter names. `resource_id` replaces `workspace_id`; `kql` is required;
`timespan`, `prefer`, and `client_request_id` are optional. A scope flag without
capture mode is an argument error. The capture host is fixed to `.azure.com` for
resources; existing workspace capture retains its current endpoint.

The collector retains actual prepared request observations and checks the
returned request against that snapshot. Configured credentials cannot occur in
retained request fields or selected response headers. GET decoded values are
also checked, so percent encoding cannot hide bearer-token characters. Original
evidence and request logs remain sensitive; this is not general secret detection.

The [protected capture transport and output contract](LOG_ANALYTICS_CAPTURE_V1.7.md)
is shared: verified TLS, one request, no retries/redirects/ambient session state,
bounded undecoded entity-body reads, private exclusive files and receipt
publication. No method or workspace fallback occurs after failure. Supported
results produce `response.json`, `context.json`, `projection.json`, and
`receipt.json`; unsupported bounded responses produce a distinct failed
observation. Receipts identify `resource-post` or `resource-get`. CAPTURED exits
2 because completeness remains unknown/incomplete; failed capture exits 1 and
interruption 130. Existing outputs are preserved. Capture receipts remain
unsigned until included in a signed case.

## Offline projection and replay

```bash
python log_analytics_context_v17.py --input response.json --context context.json \
  --format resource-post --out resource-projection.json
python log_analytics_context_v17.py --input response.json --context context.json \
  --format resource-post --compare resource-projection.json
```

Use `resource-get` for a retained GET. Signed lineage uses transformation
`v17_log_analytics_context.normalize`, version `1.7`, metadata `input_format` and
`context_artifact_id`. Context remains a separately bound second input subject
to reference and cycle checks. Verification authenticates the archive before
replay and never acquires or extracts evidence to execute it.

## Acceptance and release assurance

`v17_log_analytics_resource_selftest.py` covers synthetic POST/GET acquisition,
partial/error-free results, separately signed offline replay, and resource
substitution. All 142 focused regressions cover endpoint/scope boundaries,
permission observations, re-signed substitutions, selected credential checks,
failure behavior, CLI selection, and golden workspace capture compatibility.
Full source and extracted-package gates require these tests. Independent release
verification conditionally requires all new files and matching assurance while
preserving historical releases. No live provider acquisition, service deployment,
or production permission assessment is part of acceptance.
