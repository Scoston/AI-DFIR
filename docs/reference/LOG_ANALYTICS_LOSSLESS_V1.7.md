# Lossless Log Analytics numeric replay (unreleased)

The explicit `v17_log_analytics_lossless.normalize` transformation, version `1.7`,
preserves wide integers and exact decimal/real text in retained query results.
It is a separate fixed offline adapter; existing table/context/capture profiles
keep their reviewed acceptance boundaries and hashes.

## Forensic proposition

The projection binds exact response bytes, ordered table schemas/rows, scalar
wire kinds, and original numeric text. It detects changed digits even when two
values would round to the same ordinary floating-point number. It also
distinguishes JSON numbers from numeric strings, negative zero from zero,
trailing zeroes, and exponent spelling.

Replay establishes reproducibility of this projection only. It does not execute
KQL, authenticate a provider, establish human attribution or effective query
scope, recover rounded values from an earlier export, or prove complete
collection. Error-free/empty responses remain unknown; PartialError is incomplete.
Numeric result rows may be aggregations and are not assumed to count raw events.
Existing Evidence Pack quality and conclusion gates remain required.

The [Logs query REST definitions](https://learn.microsoft.com/en-us/rest/api/logsquery/query/execute?view=rest-logsquery-v1)
enumerate column types and include numeric-string examples. Microsoft describes
Kusto [decimal](https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/decimal?view=microsoft-fabric)
as a wide decimal type. This adapter's bounded decimal-value profile uses a
96-bit coefficient and scale through 28, corresponding to the documented
[System.Decimal value representation](https://learn.microsoft.com/en-us/dotnet/api/system.decimal?view=net-9.0).
These are explicit local acceptance rules, not proof that a provider emitted a
valid value or that every provider export format is supported.

## Scalar rules

Select `tables` for an ordinary response envelope or `resource-tables` to also
allow the bounded opaque `permissions` object. Table/column envelope validation,
duplicate names, row width/order, partial-error handling and global dimensions
are shared with the [original table profile](LOG_ANALYTICS_REPLAY_V1.7.md).

| Declared column | Accepted present value | Projected observation |
|---|---|---|
| `int` | Integer JSON token or numeric string in signed 32-bit range | Exact numeric text and wire kind |
| `long` | Integer JSON token or numeric string in full signed 64-bit range | Exact numeric text and wire kind |
| `real` | JSON number token or numeric string passing a finite, non-underflowing binary64 conversion check | Original text; the converted float is never retained or hashed |
| `decimal` | JSON number token or numeric string whose exact value fits coefficient magnitude ≤ 2^96−1 and decimal scale 0–28 | Original text, without rounding or arithmetic on the evidence value |
| `bool` | JSON Boolean | Boolean value; string Booleans are rejected |
| `datetime` | Existing explicit-offset RFC3339 string profile | Original string/fraction |
| `string`, `guid` | String; GUID syntax additionally checked | Opaque typed cell digest |
| `dynamic` | Any bounded JSON value, including wide numeric tokens | Opaque typed tree digest; embedded strings are not parsed |

Null is accepted distinctly in each column type. Missing cells fail row-width
validation. `timespan` columns and other types remain unsupported.

Numeric strings must match strict JSON number syntax; no whitespace, leading
plus, leading zeroes, underscores, `NaN`, or `Infinity`. Integer columns reject
decimal points and exponent notation. Every number token and numeric string is
at most 128 ASCII characters. Decimal bounds are checked with exact integer
arithmetic independent of floating-point rounding or ambient decimal precision.
Trailing zeroes may be removed solely for checking whether the value fits; the
original text is always preserved. Zero stays zero even with an unusual bounded
exponent spelling. Opaque dynamic/metadata number tokens are preserved without
claiming a declared scalar range.

## Number-token tree and hashing

`v17_numeric_json.document` rejects duplicate keys, invalid UTF-8/surrogates,
non-JSON constants, malformed numeric syntax, and excessive bytes/depth/nodes.
It retains every JSON number as an immutable number token before any float
parsing. Each JSON kind is tagged before canonical hashing:

| JSON kind | Tagged representation |
|---|---|
| Number | `["number", "<original token>"]` |
| String | `["string", "<decoded string>"]` |
| Boolean | `["boolean", true]` or `["boolean", false]` |
| Null | `["null"]` |
| Array | `["array", [<tagged children>]]` |
| Object | `["object", {"<key>": <tagged value>}]` |

RFC8785 canonicalization is applied to this tagged representation, whose number
tokens are strings. This does **not** redefine RFC8785 numeric canonicalization
or claim that wide numbers are ordinary JCS numbers. Tagging every kind prevents
a retained array/object from impersonating a numeric tag. Object keys retain
RFC8785 canonical ordering; original full-source bytes still bind key order,
whitespace and escape spelling.

The encoding identifier is `ai-dfir/json-number-token-tree/v1`. Row, cell, table,
column/row binding, and opaque response digests explicitly identify token-tree
hashing. Column descriptors contain only validated strings, so `schema_sha256`
still uses ordinary RFC8785 JSON and records that distinction. Numeric cells
retain `numeric_text`, `json_kind`, and `value_representation`; no wide value is
written as a potentially rounded JSON number in the projection.

Inputs/outputs retain the 8 MiB limits and shared 32-table, 256-column, 2,000-row,
50,000-cell, depth-32 and 200,000-node budgets. Each encoded row token tree must
fit 1 MiB, accounting for tagging expansion. Output canonical bytes and structure
are bounded again. Permission metadata is opaque, hash-bound and unverified.

## CLI and signed replay

```bash
python log_analytics_lossless_v17.py --input retained-response.json \
  --format tables --out new-lossless-projection.json
python log_analytics_lossless_v17.py --input retained-response.json \
  --format tables --compare new-lossless-projection.json
```

Use `resource-tables` when the permissions envelope is present. Existing output
files are preserved. Routine summaries contain counts/digests and state, with
redacted failures; values stay in the evidence projection. Normalize/compare
success exits 0; mismatches, malformed input or output conflicts exit 1.

Signed lineage uses transformation `v17_log_analytics_lossless.normalize`,
version `1.7`, metadata `{"input_format":"tables"}` or `resource-tables`, and
separately bound response/projection artifacts. Verification authenticates the
archive before replay. Unknown versions remain unsupported; input cannot select
an import, process, network action, or extra parser option.

This adapter is response-only. Automatic capture and retained-context binding
continue to use their original table profile, rejecting unsupported numeric
responses while preserving bounded raw acquisition evidence as documented. A
lossless projection does not retroactively make a failed capture receipt complete.

## Acceptance and release assurance

The synthetic self-test covers wide integers, precise decimals, numeric strings,
negative zero, resource permission metadata, partial responses and signed offline
replay. All 171 focused regressions cover lexical/type/range limits, hash-tag
collisions, number spelling, Decimal-context independence, source-byte binding,
malformed and excessive structures, re-signed digit/type/zero substitutions,
unknown transform versions, unverified archives, and CLI output protection.
Two golden original projections preserve reviewed partial/error-free hashes.

Full source and extracted-package gates require the self-test and regressions.
Independent package verification conditionally requires all new files and
matching assurance while preserving historical releases. No new dependencies,
real incident data, live provider query or deployment are part of acceptance.
