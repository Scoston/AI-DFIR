# Checkpoint policy issuer quorum

This implemented development profile is unreleased and is not included in the
published v1.7.0 assets. It extends [authenticated policy updates](CHECKPOINT_POLICY_UPDATES_V1.7.md)
with a verifier-approved threshold of distinct Ed25519 issuer keys. It adds no
new detector or Evidence Pack coverage.

The separate unreleased [signed issuer governance profile](CHECKPOINT_POLICY_GOVERNANCE_V1.7.md)
adds root rotations approved by both the current and replacement quorums, and
atomic activation of root and policy. The direct-trust workflow below remains
available for deployments that provision issuer configuration externally.

## Assurance and limits

A deployment can require two of three approved issuer keys before accepting a
policy update. One issuer cannot satisfy that requirement by repeating its
signature, renaming its key, using the older single-issuer format, or combining
approvals of different policies. Each signature also binds the exact approved
issuer configuration, including its threshold, keys, tenant, and policy ID.

The verifier supplies that configuration independently of the delivered package.
The existing transactional revision store, current-clock validity checks, case
scope, and manifest-bound checkpoint trust still apply. The quorum can only
narrow acceptance. A passing quorum cannot rescue tampered evidence, a revoked
checkpoint key, or an invalid required timestamp.

**Distinct keys are not proof of independent people or organizations.** Operators
must assign custodians and keep their keys separately controlled if they need
that protection. The report records `issuer_custodian_independence: NOT_ASSESSED`.
A threshold of one is supported explicitly but has no protection against one
approved issuer key being compromised. Compromise of enough approved keys, or
administrative replacement of verifier trust, remains outside this guarantee.

This is a local policy approval profile, not a complete implementation of
[The Update Framework](https://theupdateframework.github.io/specification/latest/).
This quorum profile alone provides no signed root-update protocol; that is
supplied by the separate governance extension. Neither provides a network
delivery service, HSM integration, or historical authorization proof.
Store backup rollback still requires an independently retained minimum revision;
signed expiry still depends on the verifier's system clock.

## Exact formats

Quorum issuer trust has exactly the following fields:

| Field | Required value |
| --- | --- |
| `schema` | `ai-dfir/checkpoint-policy-issuer-quorum/v1.7` |
| `tenant_id`, `policy_id` | Nonempty strings identifying one namespace. |
| `threshold` | Integer from 1 through the number of distinct approved keys; booleans are rejected. |
| `keys` | One to 32 entries, each containing only `key_id` and `public_key_hex`. |

Key IDs are `sha256:` plus the SHA-256 of the raw 32-byte Ed25519 public key.
Public keys use 64 lowercase hexadecimal characters. Aliases, duplicate keys,
unknown fields, empty quorum sets, and impossible thresholds fail. Every approved
quorum issuer key must be separate from every checkpoint key in the policy,
including approved issuers that did not sign the particular package.

A quorum package has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema` | `ai-dfir/quorum-signed-checkpoint-key-policy/v1.7` |
| `signature_algorithm` | `Ed25519` |
| `issuer_trust_sha256` | SHA-256 of the normalized, RFC 8785 canonical approved quorum configuration. |
| `policy` | Complete validated `ai-dfir/checkpoint-key-policy/v1.7` object. |
| `signatures` | One to 32 distinct entries, each containing only `issuer_key_id` and `signature_hex`. |

Each issuer signs RFC 8785 canonical JSON containing `schema`,
`signature_algorithm`, `issuer_trust_sha256`, `policy`, and that issuer's
`issuer_key_id`. The signature list is excluded so custodians can append separate
approvals. The quorum schema separates this signing context from the existing
single-issuer profile. Signatures use 128 lowercase hexadecimal characters.

Before hashing, trust keys are sorted by key ID and signatures by issuer key ID.
Reordering those arrays does not change identity; duplicates are rejected before
sorting. All supplied signatures must be valid and trusted, even when enough
other signatures already meet the threshold. Removing signatures below the
threshold fails. Adding or removing a signature changes the normalized envelope
digest, so an already stored revision cannot be replaced by that changed package.

Strict UTF-8 JSON parsing rejects duplicate members and non-finite numbers.
Signed input is bounded to 1 MiB plus 16 KiB, enclosed policy to 1 MiB, issuer
trust to 64 KiB, and PEM input to 16 KiB. Store limits remain unchanged.

## Separate-custodian workflow

The verifier administrator independently approves three public keys and requires
two signatures. The following uses existing organization-provisioned keys:

```bash
python checkpoint_policy_v17.py trust \
  --tenant tenant-1 --policy-id investigation-checkpoint-keys --threshold 2 \
  --issuer-public-key /trusted/issuer-a.pub.pem \
  --issuer-public-key /trusted/issuer-b.pub.pem \
  --issuer-public-key /trusted/issuer-c.pub.pem \
  --out /trusted/policy-quorum.json
```

Each custodian independently checks the policy and approved configuration. On
the first custodian's system:

```bash
python checkpoint_policy_v17.py sign \
  --policy checkpoint-policy.json --issuer-trust /trusted/policy-quorum.json \
  --issuer-private-key /private/issuer-a.pem --out partial-policy.json
```

With two signatures required, this returns `PARTIALLY_SIGNED`. Deliver the public
partial package to another approved custodian, who verifies the prior approval
and adds their own signature on their own system:

```bash
python checkpoint_policy_v17.py cosign \
  --signed-policy partial-policy.json --issuer-trust /trusted/policy-quorum.json \
  --issuer-private-key /private/issuer-b.pem --out approved-policy.json
```

Both commands create new outputs and refuse to overwrite existing files. They
make no network calls and do not collect other custodians' private keys.
`SIGNED` means sufficient signatures have been collected under the supplied
configuration; it is not acceptance. Signing can prepare a future-dated policy.
Acceptance separately checks current validity, independent trust, and revision.
CLI output includes `acceptance_performed: false` for signing commands.

On the verifier, initialize a new store only during first provisioning:

```bash
python checkpoint_policy_v17.py accept \
  --signed-policy approved-policy.json --issuer-trust /trusted/policy-quorum.json \
  --store /trusted/checkpoint-policies.sqlite --initialize
```

Omit `--initialize` for subsequent updates. A partial quorum cannot create a store
or change an existing revision. The existing `show` command reauthenticates all
approvals. To require the approved store during case verification:

```bash
python verify_case_v17.py --zip case.zip --export-public-key /trusted/export.pub.pem \
  --checkpoint-policy-store /trusted/checkpoint-policies.sqlite \
  --policy-issuer-trust /trusted/policy-quorum.json \
  --require-authenticated-key-policy --format json
```

The same configuration works on export and replay. The issuer trust schema
selects the approval requirement; a single-issuer package cannot satisfy quorum
trust, even when its threshold is one. Quorum packages likewise cannot silently
fall back to legacy issuer trust. Existing invocations without `--threshold` or
quorum signing configuration retain their prior single-issuer behavior.

## Rotation, migration, and recovery

Changing the approved threshold or issuer set changes its digest. All prior
approvals then fail against that new configuration, including when an unused
issuer is added or removed. Obtain fresh approvals over a higher policy revision
using the independently approved replacement configuration. A replacement quorum
can update the store without approval by an issuer that has been removed, while
preserving the existing revision floor.

To migrate a single-issuer store, approve the quorum configuration independently,
collect the required signatures on a higher policy revision, and accept it into
the existing store. Do not reinitialize or delete the store. Coordinate the
verifier configuration change with acceptance: there is no atomic transaction
spanning the external trust file and the store, and checks during that change
can fail closed. This is operator-managed trust replacement, not a signed
root-rotation protocol authorized by the old quorum.

Use the existing independent `--minimum-policy-revision` after backup recovery.
Protect that floor outside the restored database. Quorum signatures do not make
a valid old whole-store backup distinguishable from the latest database.

## Reports, API, and acceptance

The existing authentication report adds `approval_profile`, `issuer_key_ids`,
`required_signatures`, `valid_signatures`, and `issuer_custodian_independence`.
For quorum approval, `issuer_key_id` is null and the plural field identifies all
verified signers. Trust/policy/envelope digests, revision, current evaluation
time, acceptance time, and rollback mode remain recorded. Failed quorum checks
appear as authentication failures and block required export/reconstruction.

`sign_quorum_policy` and `cosign_quorum_policy` return detached package objects.
`validate_quorum_trust` and `validate_quorum_envelope` validate structure;
`verify_quorum_signatures` checks signatures and configuration without clock or
store acceptance. Use `authenticate_key_policy`, `accept_policy_update`, or
`load_policy_store` for the corresponding complete checks. Case API arguments
are unchanged from the authenticated policy update profile.

The synthetic self-test exercises a two-of-three approval, partial rejection,
revocation, and blocked reconstruction. The 67 focused tests cover malformed
inputs, duplicate and mixed approvals, configuration binding, rotation,
migration, concurrent updates, time boundaries, stored-signature tampering,
all affected CLIs, preserved destinations, and timestamp/evidence composition.
The quorum milestone brought the total to 344 tests; signed governance adds 87,
for 431. New packages must include this profile and
passing extracted-source assurance results; published v1.7.0 verification keeps
its prior contract. No new dependency or licensing change is required.
