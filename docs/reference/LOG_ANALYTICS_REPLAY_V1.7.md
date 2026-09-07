# Log Analytics query-result import and offline replay

This development profile is unreleased. It projects retained native query-result
JSON into ordered, typed, digest-bound tables and compares that projection
offline. It does not run KQL, acquire evidence, authenticate Azure origin, or
reassess whether a query answered the investigation question.

## Input profile and partial errors

The separate [resource table format](LOG_ANALYTICS_RESOURCE_V1.7.md),
`--format resource-tables`, also accepts bounded opaque permission observations.
The original `tables` format below retains its existing hashes and boundaries.

Select `--format tables` for a single native response body containing a required
`tables` array. The only other accepted top-level fields are `error`, `statistics`,
and `render`. Every table requires exactly `name`, `columns`, and `rows`; each
column requires exactly `name` and `type`. Columns must be nonempty and have
unique names within a table. Names remain case-sensitive. Every row must be an
array with exactly one cell per column, including explicit nulls where retained.
The entire import fails on a malformed table, unsupported type, or row-width
mismatch. No table, column, or row is silently skipped.

Microsoft's [Log Analytics response format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format)
defines the table/column/row layout and explains that HTTP 200 may include an
`error` with code `PartialError` alongside usable results. This profile handles
that distinction explicitly:

| Retained response | Projection behavior | Collection completeness |
|---|---|---|
| No `error` field | `response_state: NO_ERROR_RECORDED` | Unknown (`null`) |
| Object with exact code `PartialError` and valid tables | `response_state: PARTIAL`, full error digest retained | False |
| Fatal/unknown error code, null/nonobject error, or malformed details list | Import fails; preserve the source separately | No projection |

When present, error `details` must be a bounded array of objects. Error messages
and nested details remain opaque and digest-bound; they are not copied into
reports. Statistics and render values also retain absent/null/present digest
states. They never supply trusted query configuration, completeness, or commands.

An empty tables array or a table with zero rows never proves that an activity did
not occur. Query rows may represent aggregates, joins, aliases, or transformed
values. `row_count` counts retained rows, not underlying events. Preserve request
text, workspace/resource scope, time range, HTTP status/headers, query options,
collection receipts, and any other exports as separate evidence with lineage.
This response-only profile reports `request_scope_verified: false`.
The separate [retained request-context profile](LOG_ANALYTICS_CONTEXT_V1.7.md)
binds a preserved workspace POST request assertion to these exact response bytes
and validates a second context artifact in signed lineage. It also leaves actual
execution, effective scope, and collection completeness unverified.

The existing `azure_foundry_logs` collector now reports collection completeness
as false when any response error is present and unknown otherwise. Its existing
Boolean receipt field is false in both cases, with the distinction retained in
`request.collection_complete` and limitations. The collector CLI consequently
uses its existing incomplete-result exit code 2, while preserving acquired data.
HTTP success alone cannot mark these collections complete. Its endpoint, request,
credentials, and raw response preservation are unchanged; no new acquisition
occurs during normalization or replay.
The separate [automatic capture option](LOG_ANALYTICS_CAPTURE_V1.7.md) explicitly
acquires a workspace POST response and records compatible request context. Its
new directory/receipt output contract is opt-in; the legacy collector API and
response-only command keep their existing behavior.

Native Activity Log REST `value`/`nextLink` exports use the separate
[Azure Activity Log profile](AZURE_ACTIVITY_REPLAY_V1.7.md). Batch responses,
combined pages, SDK-converted row objects, CSV/JSONL, compression, Kusto streaming
frames, and unrecognized envelope extensions are outside this profile. Preserve
any separately authorized conversion as its own transformation.

## Cell types and content policy

This parser implements the following explicit subset. Other type names,
including decimal and timespan, fail instead of falling back to strings.

| Declared column type | Accepted nonnull JSON value | Projected value |
|---|---|---|
| `bool` | Boolean | Retained, including false |
| `int` | Integer within signed 32-bit range | Retained |
| `long` | Integer within RFC 8785 safe range, ±9,007,199,254,740,991 | Retained; wider native integers require a separate lossless profile |
| `real` | Finite number, excluding Booleans | Retained without string coercion |
| `datetime` | Valid calendar timestamp with explicit RFC3339 offset and up to nine fractional digits | Original string retained without rounding or UTC conversion |
| `guid` | Hyphenated 8-4-4-4-12 hexadecimal string | Hashed; never resolved |
| `string` | String, including empty text | Hashed |
| `dynamic` | Any bounded JSON value | Hashed without interpreting its contents |

Null is retained as an explicit cell state for every supported column type. It
never becomes zero, false, or an empty string. Every cell records its column
ordinal, JSON kind, value digest, and whether a value was retained. String, GUID,
and dynamic cell contents are omitted even when the dynamic value is numeric.
Text inside a dynamic cell is never parsed again; encoded JSON and a native
object remain distinct. Outer JSON still has strict duplicate-key and Unicode
validation, including actual objects stored in dynamic cells.

For example, the [AzureActivity table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity)
distinguishes string `Claims`/`Authorization`/`Properties` columns from their
dynamic `_d` counterparts. The parser keeps each column separately. That reference
also defines AzureActivity `TenantId` as the Log Analytics workspace ID; this
profile does not turn column names into inferred tenant, actor, or source identity.

Access controls still apply to the projection: column aliases, table names,
timestamps, numeric values, and hashes may be sensitive. The retained original
is not redacted by producing a projection.

## Binding and interpretation

The projection records the exact retained input file's SHA-256, each table's
canonical digest, each ordered column schema's digest, and each row's canonical
digest. A separate row binding hashes both the ordered column descriptors and
the row. Identical values under renamed, reordered, or retyped columns therefore
have different bindings.

Tables, columns, and rows keep their recorded order and one-based ordinals.
Repeated table names and duplicate/conflicting rows remain intact. They are not
flattened into a dictionary or deduplicated. Timestamps do not sort records,
prove clock correctness, or establish causal order. A table named PrimaryResult,
an identity-like column, or a recorded success flag does not authenticate the
source or prove a downstream outcome.

## Commands and signed-case integration

```bash
python log_analytics_v17.py --input retained-response.json \
  --format tables --out query-projection.json

python log_analytics_v17.py --input retained-response.json \
  --format tables --compare query-projection.json
```

The CLI reads bounded regular files and exclusively creates a new output,
preserving existing source files, destinations, and symlink targets. Creation or
matching comparison exits 0, including a correctly projected partial response;
the report prominently retains `PARTIAL` and `collection_complete: false`.
Exit 0 establishes projection/replay success only. Invalid/unavailable input,
conflicting output, or comparison failure exits 1; malformed arguments exit 2.
Runtime errors omit content and paths.

Preserve the source and projection as separate EvidenceArtifact records in the
same case. Ledger-bind a derived-from EvidenceRelationship from source to
projection with the usual case/artifact IDs and timestamp plus:

```json
{
  "relationship_type": "derived-from",
  "transformation": "v17_log_analytics.normalize",
  "transformation_version": "1.7",
  "metadata": {"input_format": "tables"}
}
```

Metadata must contain exactly input_format. Follow
[Investigation replay](INVESTIGATION_REPLAY_V1.7.md) for record binding, signing,
and authorized case export, then run:

```bash
python replay_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --replay-transforms --out replay.json
```

The verifier reads verified bytes from the same open archive without extraction.
It compares the entire projection using RFC 8785; projection whitespace can vary,
but changed source whitespace changes the source digest and needs a new projection.
An integrity-valid incorrect projection produces replay FAIL. Unsupported
transform versions produce INCOMPLETE. Both requested-replay outcomes exit 1.
Required trust/timestamp gates still apply independently and can block replay.
A matching partial projection can PASS while collection remains explicitly
incomplete. Replay never calls Azure, executes KQL, invokes a model, or selects
code from evidence.

## Bounds and acceptance

Input and output each allow at most 8 MiB. The profile permits at most 32 tables,
256 columns per table, 2,000 rows total, 50,000 cells total, and 1 MiB canonical
JSON per row. Metadata names/types/codes allow 4,096 characters and no control
characters. A partial-error details array allows at most 128 objects.

Input and output each have separate 32-level and 200,000-node budgets, including
keys. All limits apply together. Rows/cells are counted across every table before
projection; adding tables cannot reset those budgets. The output must fit its
own replay limits. Unknown opaque fields are still bounded. Invalid UTF-8,
unpaired surrogates, duplicate JSON keys, nonfinite numbers, and unsafe RFC 8785
integers fail without coercion or fallback.

```bash
python v17_log_analytics_selftest.py
python -m pytest tests/test_v17_log_analytics.py -q
python scripts/release_check.py --full
```

Synthetic acceptance covers retained results both with and without PartialError
and detects an incorrect cell projection in an otherwise valid signed case.
The 224 focused regressions cover typed binding, partial errors, collector receipt
semantics, precision, bounds, hostile inputs, protected source files, and offline
case gates. Source and extracted-package assurance require the same files,
regressions, and self-test. Historical v1.7.0 candidate verification remains
supported through conditional new-profile requirements.
