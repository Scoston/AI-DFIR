# Authenticated checkpoint policy updates

This implemented development profile is unreleased and is not included in the
published v1.7.0 assets. It extends [checkpoint key policy](CHECKPOINT_KEY_POLICY_V1.7.md)
with issuer signatures and a verifier-owned revision store. It does not add
model detector coverage or deploy a policy distribution service.

The separate unreleased [issuer quorum profile](CHECKPOINT_POLICY_QUORUM_V1.7.md)
adds a configurable threshold of distinct issuer approvals and offline
co-signing. The single-issuer format below retains its existing behavior.

## Assurance and trust inputs

A revoked checkpoint key must not become authorized because an evidence supplier
offers an older, still-valid active-key policy. The verifier authenticates policy
packages against independently approved issuer keys and transactionally rejects
revisions older than the one it has already accepted. Every case verification
reauthenticates the stored package against the current issuer trust and clock.

The external issuer trust file binds one `tenant_id` and `policy_id`. Downloaded
policies and case exports cannot supply, replace, or expand that authority. The
policy issuer must use a separate Ed25519 key from every checkpoint signer in
the policy. The existing export trust anchor and manifest-bound checkpoint trust
remain required. A valid policy signature cannot override damaged evidence, an
invalid checkpoint signature, or a revoked checkpoint key.

| Input | Authority and responsibility |
| --- | --- |
| Issuer trust JSON | Verifier administrator approves public keys and one tenant/policy namespace through an independent process. |
| Signed policy JSON | Untrusted transport input until its issuer, signature, scope, and current validity pass. |
| Policy store | Verifier-controlled SQLite file containing the latest locally accepted package and revision. |
| Minimum revision | Optional independently retained floor, especially for recovery from backups. |
| System UTC clock | Determines signed policy freshness; this profile supplies no trusted time source. |

Protect the store, its directory, and issuer trust using verifier-controlled
filesystem permissions. Initialization creates a new store with mode `0600`;
it does not configure directory ACLs or a hardware monotonic counter. A store
file must not be a symlink. Use one store per tenant/policy namespace.

## Package format

The signed envelope has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `ai-dfir/signed-checkpoint-key-policy/v1.7` |
| `signature_algorithm` | `Ed25519` |
| `issuer_key_id` | `sha256:` followed by the SHA-256 of the issuer's raw 32-byte public key. |
| `policy` | Complete validated `ai-dfir/checkpoint-key-policy/v1.7` object. |
| `signature_hex` | Lowercase hexadecimal encoding of the 64-byte signature. |

The signature covers the RFC 8785 canonical JSON of the envelope with only
`signature_hex` omitted. It binds the schema, algorithm, issuer identity, and
every policy field. No issuer public key is embedded in this envelope.

Issuer trust has exactly `schema`, `tenant_id`, `policy_id`, and `keys`. Its
schema is `ai-dfir/checkpoint-policy-issuers/v1.7`; each key has exactly `key_id`
and `public_key_hex`. Public keys are 32-byte Ed25519 keys encoded as 64 lowercase
hexadecimal characters. Duplicate or mismatched IDs fail. An empty list denies
all issuers. Unknown fields are rejected in both formats.

JSON must be UTF-8 with no duplicate members or non-finite numbers. Signed
documents are bounded to 1 MiB plus 16 KiB (including quorum signatures), enclosed policies to 1 MiB, issuer
trust to 64 KiB and 32 keys, and stores to 16 MiB. CLI PEM inputs are bounded to
16 KiB. Revision numbers are positive integers no larger than `2**53 - 1`.

## Operator workflow

Provision the issuer's Ed25519 key using the organization's key-management
process. Keep the private key with the policy authority. On the verifier, build
trust from the independently approved public key, using the same tenant and
policy ID as the policy:

```bash
python checkpoint_policy_v17.py trust \
  --issuer-public-key /trusted/policy-authority.pub.pem \
  --tenant tenant-1 --policy-id investigation-checkpoint-keys \
  --out /trusted/policy-issuers.json
```

Repeat `--issuer-public-key` to approve an overlap during issuer rotation.
The command formats the administrator's decision; possession of a public key
does not establish that it is an approved authority.

On the policy authority's system, sign the existing raw policy format:

```bash
python checkpoint_policy_v17.py sign \
  --policy checkpoint-policy.json \
  --issuer-private-key /private/policy-authority.pem \
  --out signed-policy.json
```

Deliver the signed JSON through the chosen transport. These tools make no
network requests. On first provisioning only, initialize the verifier's store:

```bash
python checkpoint_policy_v17.py accept \
  --signed-policy signed-policy.json \
  --issuer-trust /trusted/policy-issuers.json \
  --store /trusted/checkpoint-policies.sqlite --initialize
```

Subsequent updates use the same command **without `--initialize`**. A missing,
empty, corrupt, or incompatible store fails instead of silently starting over.
Initialization refuses an existing path. Signing and trust-file creation also
refuse to overwrite an existing output.

Inspect the accepted policy and authenticate it again:

```bash
python checkpoint_policy_v17.py show \
  --store /trusted/checkpoint-policies.sqlite \
  --issuer-trust /trusted/policy-issuers.json
```

Require the stored authenticated policy during offline verification:

```bash
python verify_case_v17.py --zip case.zip --export-public-key /trusted/export.pub.pem \
  --checkpoint-policy-store /trusted/checkpoint-policies.sqlite \
  --policy-issuer-trust /trusted/policy-issuers.json \
  --require-authenticated-key-policy --format json
```

These options also work on `case_export_v17.py create`, its `verify` subcommand,
and `replay_case_v17.py`. `--checkpoint-key-policy` and
`--checkpoint-policy-store` are mutually exclusive. A raw policy cannot satisfy
`--require-authenticated-key-policy`. Configured authentication failure blocks
export before destination replacement and prevents verification/reconstruction
from passing. No policy options retains the prior optional-policy behavior.

Use `--minimum-policy-revision 4` when an independent trusted record establishes
that at least revision 4 must be present. The floor also works on `show`. An
optional `--expected-key-policy-sha256` continues to pin the enclosed canonical
policy. Neither value should be derived from an untrusted candidate itself.

## Revision, recovery, and time semantics

Updates acquire a SQLite write transaction before comparing and replacing the
stored revision. Lower revisions fail. The exact same canonical envelope at the
same revision returns `UNCHANGED`, retaining its original acceptance time. Any
different envelope at that revision fails, including a replacement signature by
another issuer. A higher revision is required for every changed package.
Concurrent writers serialize; a failed transaction preserves the prior record.
Readers use one consistent snapshot, with its identity recorded in the report.
An update committed after that snapshot is read applies to subsequent checks.

Approve replacement issuer keys independently before accepting their packages.
A currently trusted replacement issuer can issue a higher revision even when
the previous issuer has been removed or its old policy expired. This preserves
the local revision floor. Removing the current issuer from trust immediately
denies its stored policy on the next verification. A downloaded package cannot
authorize its own issuer rotation.

**Restoring an older whole database is outside the store's rollback guarantee.**
An older valid backup can pass without an independently retained minimum
revision. Keep that floor outside the backup being restored, and require it
after recovery. Protecting issuer trust and the store is an operating assumption;
this implementation cannot defend against an administrator who replaces both.

Policies must satisfy `issued_at <= system UTC < expires_at` during acceptance
and every use. Acceptance rechecks freshness after obtaining the write lock.
`--policy-evaluation-time` cannot backdate signed-policy authentication. Signed
expiry limits use of stale packages, but the verifier cannot know that a newer
policy exists before it receives one. There is no update polling, worldwide
latest-revision proof, root-update protocol, or trusted clock. The separate
quorum extension supplies signature thresholds; this is not an implementation
of The Update Framework.

Current key revocation still denies historical checkpoints. The separate
[timestamp profile](CHECKPOINT_TIMESTAMPS_V1.7.md) can authenticate a retained TSA
receipt; it does not make a revoked key acceptable or authenticate historical
policy decisions. Online delivery, organizational issuer governance, archival
TSA revocation evidence, and historical authorization remain separate work.

## Reports and Python API

Case reports add `checkpoint_key_policy.authentication` using schema
`ai-dfir/checkpoint-policy-authentication/v1.7`. It records the status, issuer key
ID, canonical issuer-trust/policy/envelope SHA-256 values, revision, acceptance
time, current evaluation time, signature result, rollback-protection mode, and
findings. `network_performed` is always false. Acceptance time is local audit
metadata, not a trusted timestamp. An authentication failure remains separate
from the checkpoint's cryptographic validity and timestamp result.

`v17_policy_distribution.py` exposes `sign_key_policy`, `load_issuer_trust`,
`authenticate_key_policy`, `accept_policy_update`, and `load_policy_store`.
Standalone authentication checks a package's signature/scope/freshness; only
store acceptance/use adds persisted revision protection. `PolicyUpdateError`
provides a machine-readable `code`. The CLI exits 0 on success, 1 for a rejected
policy/store, 2 for argument errors, and 3 for input/configuration errors.

Case export/verification Python APIs accept `checkpoint_policy_store`,
`policy_issuer_trust`, `require_authenticated_key_policy`, and
`minimum_policy_revision`. Supply the parsed independently approved issuer trust
from `load_issuer_trust`. No caller-supplied authentication report grants trust.

## Acceptance

The synthetic self-test accepts an active policy, applies a signed revocation,
rejects rollback, and blocks reconstruction. The 66 focused tests also cover
issuer rotation, concurrent/conflicting updates, restart persistence, backup
recovery with an independent floor, malformed JSON/stores, strict validity,
embedded trust rejection, tampering, export preservation, CLI parity, and
composition with external timestamps. This milestone brought the total to 277
v1.7 tests; the subsequent quorum profile adds 67, for 344. Packaging repeats
the full gate on extracted committed source and requires
the new profile's files and assurance results. Published v1.7.0 package
verification retains its original contract. No new dependency is required.
