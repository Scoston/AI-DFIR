# Native CloudTrail import and offline replay

This development profile is unreleased and is not in the published v1.7.0 assets.
It projects selected recorded CloudTrail metadata and payload digests from
preserved native JSON. Offline replay checks whether the exact retained input
produces the recorded projection. It neither acquires AWS evidence nor validates
AWS log-file digest signatures.

## Supported inputs

Choose the format explicitly; there is no format guessing or fallback.

| Format | Required envelope | Meaning |
|---|---|---|
| `records` | `{"Records":[...]}` | Uncompressed CloudTrail log JSON |
| `lookup-events` | `{"Events":[{"CloudTrailEvent":"<JSON string>", ...}], ...}` | Retained LookupEvents response or CLI JSON export |

The Records envelope permits only Records. The lookup envelope permits Events,
NextToken, and optional SDK ResponseMetadata. It requires the embedded event;
display fields cannot replace missing native evidence. Present EventId,
EventName, EventSource, ReadOnly, and EventTime must agree with the native event.
Wrapper time can be an epoch number or timezone-aware ISO timestamp. Other
wrapper details are digest-bound but are not interpreted or used for attribution.

The event profile accepts major version 1 with numeric minor version at least 2,
including historical spellings such as 1.02. Event ID, UTC event time, source,
operation, Region, type, and a userIdentity object are required. Projected
optional fields must have their expected types when present. Missing identity
details remain null. Event categories and operation names are recorded without
guessing one from the other.

This is a bounded projection profile, not a complete AWS schema validator.
Unknown event fields remain bound by the canonical event digest. Payload fields
are opaque JSON: their structure and byte budgets are checked, then their values
are hashed. Insights, JSONL, bare arrays, CloudTrail Lake query results,
EventBridge envelopes, gzip input, and AI-DFIR's combined collector envelope
are outside this profile and are rejected. Preserve compressed originals and
any authorized decompression lineage separately. Existing legacy flat-row
normalization and live collectors keep their existing behavior.

AWS documents the native [log envelope and compressed delivery format](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html),
[event fields and version rules](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html),
and the [embedded LookupEvents event](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Event.html).

## Normalize or compare a retained export

```bash
python cloudtrail_v17.py --input retained-cloudtrail.json \
  --format records --out cloudtrail-normalized.json

python cloudtrail_v17.py --input retained-lookup.json \
  --format lookup-events --out lookup-normalized.json

python cloudtrail_v17.py --input retained-cloudtrail.json \
  --format records --compare cloudtrail-normalized.json
```

Output creation is exclusive: an existing destination, including an input path,
is preserved. Inputs must be bounded regular files. A malformed event fails the
whole operation; no partial result or silently skipped row is produced. CLI
exit 0 means normalization or comparison succeeded; exit 1 means an input,
destination, resource-limit, or comparison failure. Invalid command-line syntax
uses argparse's exit 2. Error reports omit evidence text and filesystem paths.

Normalization reports source/output SHA-256 and event count. Comparison reports
recorded/replayed output digests and PASS or FAIL. No model, network request,
subprocess, current provider catalog, or evidence-selected code is used.

## What the projection preserves

- Exact original UTF-8 input bytes have a source_sha256. Each native event has a
  separate RFC 8785 canonical digest; a lookup event also has a wrapper digest.
- Events retain input order and a one-based ordinal. Duplicate IDs, including
  conflicting repeated records, remain separate rows. No sorting, deduplication,
  correlation, addendum application, or causal ordering occurs.
- Selected fields retain event/request IDs, time, service, operation, Region,
  event category/type, recipient account, source IP, read-only/management flags,
  error code, and shared event ID.
- Caller identity and session issuer remain separate. ARN, principal ID, account
  ID, identity type, and service invocation fields are recorded claims. They do
  not establish a human actor or prove the credentials' authority.
- Request parameters, response elements, error message, resources, additional
  event data, service event details, addendum, and full userIdentity are hashed.
  Each digest distinguishes absent, explicit null, and present content.

Prompt/response bodies and accessKeyId are not deliberately copied into the
projection. Selected metadata can still contain personal or sensitive material;
this is not a general redaction or declassification tool. Retained source
artifacts still contain their original content and require normal evidence
access controls. A null or absent payload does not prove an empty request or
response; upstream logging can omit or truncate information.

## Collection and authenticity limits

A NextToken makes collection_complete false and continuation_token_present
true. The token itself is hashed. Without it, completeness remains null
(unknown), including for an empty Records or Events array. The parser cannot
know earlier pages, query filters, account/Region coverage, retention, disabled
logging, collection errors, or data lost before export. An empty result is not
proof that an activity did not happen.

[LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)
covers recent regional management events and optionally Insights; it does not
supply all CloudTrail data events. This parser rejects Insights. AWS documents
[Bedrock operation-specific logging and data-event selectors](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html).
Acquire required streams using independently authorized collection procedures;
a local parser cannot recover events that were never collected.

source_authenticity_verified remains false. Matching hashes and replay establish
internal reproducibility of preserved bytes, not AWS origin, complete collection,
a successful model invocation, downstream effect, or an approved conclusion.
An absent errorCode is not interpreted as success; errors can also occur inside
opaque response details.

## Bind the transformation into a signed case

Preserve both the exact raw export and projection as EvidenceArtifact records
within the same case. Add and ledger-bind an EvidenceRelationship with:

```json
{
  "relationship_type": "derived-from",
  "transformation": "v17_cloudtrail.normalize",
  "transformation_version": "1.7",
  "metadata": {"input_format": "records"}
}
```

Supply the case/parent/child IDs and creation timestamp as required by
[Investigation replay](INVESTIGATION_REPLAY_V1.7.md). The raw export is the parent
and projection is the child. Sign/export the completed case through the existing
authorized signing workflow. Then run:

```bash
python replay_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --replay-transforms --out replay.json
```

Reconstruction consumes verified bytes from the same open archive without
extracting members. Metadata must contain exactly input_format. An unknown
transformation version is UNSUPPORTED and makes requested replay INCOMPLETE.
A validly signed but incorrect projection can have integrity PASS and replay
FAIL; requested replay then exits 1. Required key-policy, timestamp, and other
case gates remain independent and can block reconstruction.

The full projected JSON is compared using RFC 8785. Changing raw file formatting
changes its exact-byte source digest and therefore requires a new projection.
Changing only the projection's JSON whitespace does not change its meaning.

## Limits and acceptance

Input and projected output are each capped at 8 MiB, with at most 2,000 events.
Each canonical native event is capped at 1 MiB; an embedded lookup event's UTF-8
JSON string also has that cap. Parsed trees permit at most 32 levels and 200,000
nodes (including keys); decoded lookup events share the input node budget.
Output has its own node budget. Projected metadata strings permit 1,024 characters.
All limits apply together, so a file may fail before the event-count ceiling.

Duplicate keys, invalid UTF-8, unpaired surrogates, non-finite numbers, integers
outside the RFC 8785 safe range, invalid timestamps/types, wrapper contradictions,
mixed envelopes, and exceeded limits fail. No file is silently truncated.

```bash
python v17_cloudtrail_selftest.py
python -m pytest tests/test_v17_cloudtrail.py -q
python scripts/release_check.py --full
```

Synthetic acceptance exercises both native formats in signed cases, disables
network access, and detects an incorrect projection without conflating replay
failure with integrity failure. The source and extracted-package release gates
require the same 130 focused regressions, self-test, code, and guide. The
historical v1.7.0 package-verification contract remains supported.

