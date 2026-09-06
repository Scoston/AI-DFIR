# Checkpoint key lifecycle policy

Status: implemented in development, unreleased. This optional profile extends
v1.7 offline verification and the investigation-provenance/replay extension.

## What this establishes

The export's signed manifest preserves the exporter's checkpoint trust store.
A receiving investigator can now impose an additional policy obtained through
an independent, trusted channel. This policy identifies the permitted public
keys, their lifecycle states, validity periods, tenant, and optional case scope.

Acceptance requires all existing package, signature, and signer-trust checks
plus the external policy. A policy cannot make an otherwise invalid export pass.
It never changes evidence bytes, signatures, or the packaged trust store.

The result distinguishes:

| Result | Meaning |
| --- | --- |
| `signature_valid` | The checkpoint signature passes its cryptographic checks. |
| `manifest_signer_trusted` | The export-manifest-bound trust store accepts the checkpoint key. |
| `checkpoint_key_policy.status` | The independently supplied policy accepts or rejects the key and context. |
| `signer_trusted` | Both applicable trust decisions pass. |
| `valid` | All required case verification controls pass. |

A correctly signed checkpoint from a revoked key can therefore report
`signature_valid: true`, `signer_trusted: false`, and `valid: false`.

## Trust input and policy freshness

The verifier loads the policy only from its explicit external argument. A file
inside a case export cannot supply this authority, satisfy the requirement for
a policy, or override a different external policy. The caller is responsible for
obtaining and approving the policy independently of the evidence supplier.

The policy's `issued_at` and `expires_at` bound its lifetime. The verifier records
its ID, revision, canonical SHA-256, evaluation time, and time source. An optional
expected SHA-256 pins the exact approved snapshot, preventing substitution of
an older active-key policy when a newer revoked-key policy was expected.

For a raw policy supplied directly, revision is audit metadata without an
automatically enforced monotonic counter. A still-unexpired old snapshot can be
accepted if the caller supplies it without a current hash pin. Deployments must
protect and refresh raw inputs and expected digests through their trusted process.
Computing the expected digest from an untrusted file at verification time does
not create an independent approval.

The separate unreleased [authenticated policy update profile](CHECKPOINT_POLICY_UPDATES_V1.7.md)
adds independent issuer signatures and a persisted transactional revision store.
Use its store and authentication requirement when signed updates and rollback
rejection are mandatory. Neither profile retrieves revocation data online.

## Lifecycle and time semantics

| Key state | Decision in this profile |
| --- | --- |
| `active` | Eligible only within its validity interval, with matching identity, scope, and signature. |
| `retired` | Not authorized by the supplied policy, including for older checkpoints. |
| `revoked` | Not authorized by the supplied policy, including for older checkpoints. |
| Absent key | Not authorized. An empty key list explicitly denies all keys. |

Validity intervals include their start and exclude their end. Both the
evaluation time and the claimed signing time must fall within the key interval.
Checkpoint creation must not follow signing, and signing must not follow the
evaluation time. Timestamps must be explicit UTC, using `Z` or `+00:00`.

By default, evaluation uses the verifier's current system UTC clock. An explicit
evaluation time supports reproducible reports and scenario analysis; its source
is recorded as `caller`. Neither the clock nor the supplied time is authenticated
by this profile. A policy's retired/revoked state still denies the key even when
the caller supplies an earlier evaluation time.

This is deliberately a current-policy authorization check. It does not prove
that an older signature existed before key compromise, retirement, or expiry.
A signer who controls a private key can also choose its signed timestamp.
Historical acceptance of retired/revoked keys needs additional independently
authenticated evidence. RFC 3161 describes a timestamp authority's role in
establishing that data existed before a stated time. See
[RFC 3161, introduction](https://www.rfc-editor.org/rfc/rfc3161#section-1).
The separate unreleased [checkpoint timestamp profile](CHECKPOINT_TIMESTAMPS_V1.7.md)
can authenticate that attestation. It does not override retired/revoked states
or implement historical key authorization; current policy still applies.
The separate [historical record profile](CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md)
binds a retained signed policy, issuer chain, checkpoint, and reproducible result
to an independent timestamp. It preserves current authenticated policy as a
mandatory case gate and makes no global policy-completeness claim.

For rotation, provision the replacement key through the trusted policy process,
allow a deliberate overlap of active keys, then publish a new policy revision
retiring the old key. Preserve previous policies and verification reports for
audit purposes. A retired key's old signatures can remain cryptographically
valid while failing the new policy; that does not erase or alter the evidence.

## Policy format

The exact schema is `ai-dfir/checkpoint-key-policy/v1.7`. All displayed fields are
required; unknown fields, ambiguous JSON, duplicate key IDs, unsupported
algorithms/states, invalid intervals, and mismatched public keys are rejected.

The following template intentionally contains placeholders. Replace the key
fields with an independently verified Ed25519 public key and its derived ID.
Do not include private keys or credentials.

```json
{
  "schema": "ai-dfir/checkpoint-key-policy/v1.7",
  "policy_id": "investigation-checkpoint-keys",
  "revision": 1,
  "tenant_id": "TENANT-001",
  "case_ids": ["CASE-001"],
  "issued_at": "2026-09-06T00:00:00Z",
  "expires_at": "2026-10-01T00:00:00Z",
  "keys": [
    {
      "key_id": "sha256:<SHA-256 of the 32 raw public-key bytes>",
      "public_key_hex": "<64 lowercase hexadecimal characters>",
      "signature_algorithm": "Ed25519",
      "state": "active",
      "not_before": "2026-09-01T00:00:00Z",
      "not_after": "2026-10-01T00:00:00Z",
      "status_changed_at": null,
      "reason": null
    }
  ]
}
```

`case_ids: null` deliberately authorizes any case within the policy tenant.
A non-null case list must be nonempty and contain unique identifiers.
Retired/revoked entries require a UTC `status_changed_at` no later than policy
issuance and a nonempty `reason`. Active entries require both fields to be null.
Policies are limited to 1 MiB, 1,000 keys, and 1,000 case IDs.

## CLI usage

```bash
python verify_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --tenant TENANT-001 --case CASE-001 \
  --checkpoint-key-policy /trusted/checkpoint-policy.json \
  --require-checkpoint-key-policy --format json
```

Add `--expected-key-policy-sha256 <approved-canonical-digest>` to pin the policy.
Use `--policy-evaluation-time 2026-09-06T12:00:00Z` only when intentionally
evaluating a particular time instead of the current clock.

The same four policy options are available on `case_export_v17.py create`,
`case_export_v17.py verify`, and `replay_case_v17.py`. A denied export fails before
writing its destination. A denied verification returns a nonzero exit code and
does not expose a reconstruction. A malformed policy file is a configuration
error, also with a nonzero exit code.

Existing invocations without policy options retain their previous behavior and
report `NOT_CONFIGURED`. Supplying the requirement flag, a digest pin, or an
evaluation time without a policy fails instead of silently falling back.
Deployments that require independent key policy must configure the requirement
in their verifier invocation; an optional feature cannot enforce its own use.

## Python API

```python
from case_export_v17 import verify_case
from v17_key_policy import load_key_policy

report = verify_case(
    "case.zip", "export.pub.pem",
    checkpoint_key_policy=load_key_policy("/trusted/checkpoint-policy.json"),
    require_checkpoint_key_policy=True,
    expected_tenant="TENANT-001", expected_case="CASE-001",
)
```

The corresponding export parameters and verification parameters are
`checkpoint_key_policy`, `require_checkpoint_key_policy`,
`key_policy_evaluated_at`, and `expected_key_policy_sha256`.
`evaluate_key_policy()` also supports a standalone signed-checkpoint decision;
its result alone is not full case, artifact, or ledger verification.

## Acceptance and limits

The 57 focused tests cover valid offline reconstruction, trust separation,
rotation overlap, retired/revoked keys, timestamp claims, exact validity
boundaries, tenant/case scope, pinned-policy substitution, embedded-policy
rejection, malformed/oversized policies, export refusal, and all verification
CLIs. The synthetic self-test participates in the quick and full release gates.
New release candidates must include the module, tests, documentation, and passing
policy assurance results. Already published packages retain their prior contract.

This base profile does not manage private keys, configure an HSM, claim a trusted
timestamp, or refresh revocation data over a network. Authentication of delivered
policy packages is provided by the separate update profile linked above.
