# Timestamped historical key-trust records — unreleased v1.7 profile

This profile preserves an issuer-approved checkpoint key policy, its signed root
chain, a complete signed checkpoint, and a reproducible ALLOW/DENY decision in
one RFC 3161 timestamped record. It is implemented in development and is absent
from the published v1.7.0 assets. All capture, preparation, and verification
commands operate on local files; no timestamp service is deployed or contacted.

## What a successful result establishes

With an independently approved starting root, TSA certificate pin, and CA bundle,
the verifier authenticates the complete retained issuer chain and policy. It
reproduces the decision under that policy both at the recorded local time and
throughout the interval described by the authenticated TSA time and accuracy.
The TSA binds the entire record, including the policy and decision, through a
SHA-256 imprint. The timestamp attests that this record existed by the upper
bound of that interval; it does not approve the record's contents.

[RFC 3161](https://www.rfc-editor.org/info/rfc3161/) defines accuracy as a deviation
around the TSA generation time. This profile requires an explicit signed
accuracy field with at least one component. Missing seconds, milliseconds, or
microseconds contribute zero; absent accuracy is rejected even when a service
policy might describe it elsewhere. Verification checks both interval endpoints
and all interior checkpoint-signing/key-validity boundaries. A decision that
changes anywhere in the interval is rejected. Root and policy validity use
inclusive starts and exclusive ends, so the entire interval must precede expiry.

The `recorded_at` and checkpoint `signed_at` values remain local claims. A
successful result does **not** prove the exact signing time, that a verifier or
human actually executed an earlier review, or that this was the newest policy
available to the organization. A currently compromised issuer may create a
backdated policy, but cannot reuse an older timestamp for changed record bytes.
No completeness claim is made for historical revocation evidence or external
custody history. The result applies to the retained issuer-approved inputs.

## Independent trust and current authorization

The record contains the starting anchor's digest, not an authority the verifier
may adopt automatically. Obtain the approved root anchor, TSA CA bundle, and
exact TSA certificate SHA-256 from independent channels. Retain the reported
record and request digests separately when substitution detection is required.
The request digest detects replacement of a request/response pair; the record
digest additionally identifies the expected historical decision record.

Standalone historical verification permits a root or policy that has expired
since the attested interval. The underlying
[timestamp verifier](CHECKPOINT_TIMESTAMPS_V1.7.md) still checks the TSA chain
against the current verifier clock using
[OpenSSL 3](https://docs.openssl.org/3.0/man1/openssl-ts/). TSA revocation remains
`NOT_CHECKED` and operator independence remains `NOT_ASSESSED`. This is not a
long-term archival validation or timestamp-renewal implementation.

When history is configured on case export, verification, or replay, an
independently authenticated **current policy store is also mandatory**. History
cannot enable raw-policy fallback or replace manifest signer trust, evidence
integrity, provenance, or a separately required checkpoint timestamp. A later
retirement/revocation in the current store blocks export/reconstruction even if
the retained historical record says ALLOW. Existing explicit policy evaluation
times retain their caller-claim semantics; they cannot backdate the store's
system-clock root/policy freshness checks or undo its supplied revoked state.

The verifier's protected store contains the latest revision it accepted, not a
proof of global latestness. Synchronize through the separate
[delivery profile](CHECKPOINT_POLICY_DELIVERY_V1.7.md) when appropriate and retain
independent root/policy floors for backup recovery. Verification never performs
that synchronization automatically.

## Capture, timestamp, and verify

First capture a decision from an already initialized
[governed policy store](CHECKPOINT_POLICY_GOVERNANCE_V1.7.md):

```bash
python checkpoint_history_v17.py capture \
  --store approved-policy.sqlite --anchor approved-root.json \
  --signed-checkpoint signed_checkpoint.json --tenant TENANT --case CASE \
  --minimum-policy-revision 2 --minimum-root-version 2 \
  --out key-trust-record.json

python checkpoint_history_v17.py prepare \
  --record key-trust-record.json --anchor approved-root.json \
  --out key-trust.tsq
```

Capture reads one authenticated store snapshot without modifying it. It checks
current root/policy validity and optional independent floors. A DENY decision
can be captured successfully for preservation; neither CAPTURED nor PREPARED
claims timestamp attestation. Preparation reauthenticates the record and current
authority before generating a fresh 128-bit nonce. Both commands create output
exclusively and refuse to overwrite an existing file. Optional
`--tsa-policy-oid` binds the request to a required TSA policy.

Submit the `.tsq` through your approved service process and preserve the exact
`.tsr` response. That operator step is outside these commands. Requests contain
an imprint, nonce, and protocol metadata; they do not disclose the policy,
checkpoint, tenant, or case in plaintext. Then verify offline:

```bash
python checkpoint_history_v17.py verify \
  --record key-trust-record.json --anchor approved-root.json \
  --signed-checkpoint signed_checkpoint.json --tenant TENANT --case CASE \
  --timestamp-request key-trust.tsq --timestamp-response key-trust.tsr \
  --tsa-ca-file approved-tsa-ca.pem \
  --expected-tsa-certificate-sha256 APPROVED_TSA_DER_SHA256 \
  --expected-timestamp-request-sha256 RETAINED_REQUEST_SHA256 \
  --expected-record-sha256 RETAINED_RECORD_SHA256
```

The uppercase digests are placeholders for independently obtained lowercase
64-character SHA-256 values. Verification exits 0 only for an authenticated
ALLOW, 1 for a failed check or authenticated DENY, 2 for invalid command syntax,
and 3 for local file/configuration errors. Read the JSON status and findings;
do not infer approval merely because a record was captured or timestamped.

## Case and replay integration

Add the following to `verify_case_v17.py`, `case_export_v17.py create/verify`, or
`replay_case_v17.py`, alongside their existing case/key arguments:

```bash
--checkpoint-policy-store current-policy.sqlite \
--policy-root-anchor current-approved-anchor.json \
--key-trust-record key-trust-record.json \
--key-trust-root-anchor historical-approved-anchor.json \
--key-trust-timestamp-request key-trust.tsq \
--key-trust-timestamp-response key-trust.tsr \
--key-trust-tsa-ca-file approved-tsa-ca.pem \
--expected-key-trust-tsa-certificate-sha256 APPROVED_TSA_DER_SHA256 \
--expected-key-trust-request-sha256 RETAINED_REQUEST_SHA256 \
--expected-key-trust-record-sha256 RETAINED_RECORD_SHA256 \
--require-key-trust-history
```

Any partial configuration fails even without the requirement flag. The current
and historical anchors have separate explicit inputs; neither comes from the
case or historical record. A direct issuer-trust policy store remains supported
for the current-policy gate. Configured history must bind the exact complete
checkpoint verified in the case. Export refuses a failed gate before replacing
the destination; verification and replay omit reconstruction on failure.

## Record and report contract

The strict JSON record uses `ai-dfir/checkpoint-key-trust-record/v1.7`. It contains
tenant/case IDs, starting anchor digest, local `recorded_at`, complete signed
checkpoint, root rotations, quorum-signed policy, and decision. The decision
contains status, signer key ID, key state, and sorted unique finding codes.
Unknown fields, duplicate JSON keys, malformed signatures, oversized content,
and mixed scope are rejected. The total bound is 5 MiB plus 48 KiB; the root
chain remains limited to 4 MiB and 64 rotations, with existing policy limits.

The canonical timestamp statement uses the distinct schema
`ai-dfir/key-trust-record-timestamp-statement/v1.7`, tenant/case IDs, and canonical
record SHA-256. An ordinary checkpoint timestamp cannot substitute for this
record timestamp, or vice versa. Existing checkpoint timestamp APIs retain
their previous format and optional behavior.

Case reports expose `checkpoint_key_trust_history`; standalone verification
returns that same result. Its schema is
`ai-dfir/checkpoint-key-trust-history/v1.7`.

| Field | Meaning |
| --- | --- |
| `status` | PASS authenticates/reproduces a record, including a DENY; FAIL rejects it; NOT_CONFIGURED/NOT_RUN do not attest anything |
| `historical_key_trusted` | True only after successful verification of an ALLOW decision |
| `record_existence_attested`, `decision_reproduced` | True only after authority, timestamp, scope, and interval checks all pass |
| `recorded_at_claim`, `recorded_decision` | Retained local time and reproduced result |
| `tsa_interval` | Authenticated earliest/latest bounds, including accuracy |
| `record_sha256`, `policy_sha256`, `root_sha256`, `anchor_sha256` | Exact verified inputs |
| `policy_revision`, `root_version`, `rotations_verified`, `authority` | Retained revision and verified issuer approvals |
| `timestamp` | Separate cryptographic receipt report with subject binding and TSA limits |
| `current_authorization_evaluated`, `latest_policy_proven`, `historical_signing_time_proven`, `actual_prior_verifier_execution_proven` | Always false for this historical result; current case policy has its own report |

The synthetic offline self-test and 85 focused regressions cover authenticated
history, signed time-boundary attacks, substitution, current revocation,
independent gates, CLI behavior, and output preservation. Source and extracted
release gates require those results and all profile files. Published v1.7.0
packages keep their original verification contract. No new dependency is added.
