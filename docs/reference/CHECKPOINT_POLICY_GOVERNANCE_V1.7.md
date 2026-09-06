# Signed issuer-root rotation and atomic policy activation

This implemented development profile is unreleased and is not included in the
published v1.7.0 assets. It extends [policy issuer quorums](CHECKPOINT_POLICY_QUORUM_V1.7.md)
with signed continuity between issuer configurations and a governed policy store.
It adds no detector or Evidence Pack coverage.

## Assurance

An issuer configuration must not be replaced just because a delivered package
names new keys. A rotation must extend the exact currently accepted root by one
version and carry approvals meeting both the previous and replacement issuer
quorums. Each signature binds its role, the predecessor digest, and the complete
replacement root. Both groups approve the transfer of authority; the replacement
group separately signs the accompanying checkpoint policy.

Activation commits the new root, retained rotation history, and higher policy
revision in one SQLite transaction. A rejected policy or failed write leaves the
previous pair intact. Readers obtain one consistent snapshot and verify the
complete retained chain from an independently supplied starting root. Rotation
does not replace that external anchor file or reset the policy revision floor.

This uses the continuity principles of sequential versions and approval by both
old and new quorums described in [TUF's root-update workflow](https://theupdateframework.github.io/specification/latest/).
This application-specific profile is **not a TUF implementation**. Its issuer
quorum governs both policy signing and root changes; it does not add separate
TUF root/targets/timestamp roles, repository services, or automatic key custody.

## Trust inputs and formats

| Input | Authority |
| --- | --- |
| Independent root anchor | Administrator-approved starting root, retained outside the evidence package and governed database. |
| Signed rotation | Untrusted until both role quorums, exact predecessor, version, scope, and signatures pass. |
| Signed policy | Must meet the replacement root's issuer quorum and current policy checks. |
| Governed store | Verifier-controlled version 2 SQLite database retaining the current policy and root chain together. |
| Independent minimum versions | Optional separately retained policy/root floors to detect restoration of an old whole database. |

A root has exactly `schema`, `version`, `issued_at`, `expires_at`, and
`issuer_trust`. Its schema is `ai-dfir/checkpoint-policy-issuer-root/v1.7`;
`issuer_trust` is a validated quorum configuration. Version is a positive integer
at most `2**53 - 1`. Time fields are explicit RFC 3339 UTC instants, with issuance
before expiry. The starting anchor can be any independently approved version;
every subsequent rotation must advance by exactly one.

A rotation has exactly the following fields:

| Field | Required value |
| --- | --- |
| `schema` | `ai-dfir/checkpoint-policy-root-rotation/v1.7` |
| `signature_algorithm` | `Ed25519` |
| `previous_root_sha256` | Canonical SHA-256 of the exact predecessor root. |
| `root` | Complete replacement root, with the same tenant and policy ID. |
| `signatures` | Object containing exactly `previous` and `replacement` signature lists. |

Each signature entry has exactly `issuer_key_id` and `signature_hex`, using the
existing SHA-256 key ID and lowercase Ed25519 signature encoding. Signature
material is RFC 8785 canonical JSON of the rotation with `signatures` omitted
and the signing `role` and `issuer_key_id` added. Role binding prevents an old
approval from being copied into the replacement group, even when a key belongs
to both groups. A shared key can deliberately sign each role separately.

Each distinct key counts once per role. All supplied signatures must verify,
including extras beyond the threshold. Duplicates, unknown keys, unsupported
fields, mixed predecessors, skipped versions, and namespace changes fail.
Replacement issuance cannot precede predecessor issuance. Quorum key lists and
signature groups are sorted by key ID before canonical hashing.

Partial groups are permitted during signing; they never satisfy acceptance.
JSON must be UTF-8 without duplicate members or non-finite numbers. Roots are
bounded to 68 KiB, rotations to 100 KiB, and each role to 32 signatures. The
retained chain is limited to 64 rotations and 4 MiB; the existing 16 MiB store
limit and filesystem protections also apply. No unbounded chain is replayed.

## Provisioning and migration

Use organization-approved issuer keys, root lifetimes, and policy revisions.
The dates below are examples and must be replaced with the approved current
validity window. First format the independently approved starting root:

```bash
python checkpoint_governance_v17.py root \
  --issuer-trust /trusted/current-quorum.json --version 1 \
  --issued-at 2026-09-06T00:00:00Z --expires-at 2026-10-06T00:00:00Z \
  --out /trusted/root-anchor.json
```

This formats an administrator's decision; it does not approve keys on the
administrator's behalf. A root from an evidence supplier cannot supply this
authority. Protect the anchor, store, and directories with verifier-controlled
permissions. Initial creation uses mode `0600`; it does not configure directory
ACLs or hardware-backed storage.

For a new store, supply a currently valid quorum-signed policy:

```bash
python checkpoint_governance_v17.py initialize \
  --anchor /trusted/root-anchor.json --signed-policy approved-policy.json \
  --store /trusted/checkpoint-policies.sqlite
```

For an existing quorum store, use explicit migration instead of initialization:

```bash
python checkpoint_governance_v17.py migrate \
  --anchor /trusted/root-anchor.json --store /trusted/checkpoint-policies.sqlite
```

Migration authenticates the current policy against the anchor's quorum, requires
current policy/root validity, and preserves the policy revision and original
acceptance time. It adds governance state transactionally; failure restores the
original format. A legacy single-issuer policy must first be upgraded to the
quorum profile. Reading a legacy store never migrates it implicitly, and neither
missing stores nor existing paths are silently reinitialized.

## Collecting rotation approvals

Export the currently authenticated root for custodians to review:

```bash
python checkpoint_governance_v17.py export-root \
  --anchor /trusted/root-anchor.json --store /trusted/checkpoint-policies.sqlite \
  --out current-root.json
```

Prepare `next-root.json` using the `root` command with the approved replacement
quorum, version N+1, and its approved lifetime. Each custodian independently
reviews the predecessor and proposed successor. For a two-of-three rotation,
collect these approvals on the corresponding custodians' own systems:

```bash
python checkpoint_governance_v17.py sign \
  --previous-root current-root.json --next-root next-root.json \
  --role previous --issuer-private-key /private/old-a.pem --out rotation-1.json

python checkpoint_governance_v17.py cosign \
  --previous-root current-root.json --rotation rotation-1.json \
  --role previous --issuer-private-key /private/old-b.pem --out rotation-2.json

python checkpoint_governance_v17.py cosign \
  --previous-root current-root.json --rotation rotation-2.json \
  --role replacement --issuer-private-key /private/new-a.pem --out rotation-3.json

python checkpoint_governance_v17.py cosign \
  --previous-root current-root.json --rotation rotation-3.json \
  --role replacement --issuer-private-key /private/new-b.pem --out approved-rotation.json
```

The tools verify collected approvals before appending another. They never
collect another custodian's private key, contact a service, or overwrite an
existing output. Signing reports `PARTIALLY_SIGNED` until both quorums are met.
`SIGNED` still means signatures collected, not activated authority;
`acceptance_performed` remains false.

Use `checkpoint_policy_v17.py sign` and `cosign` with the replacement quorum to
prepare `next-policy.json`, at a policy revision higher than the stored one.
Then activate the signed rotation and new policy together:

```bash
python checkpoint_governance_v17.py accept \
  --anchor /trusted/root-anchor.json --store /trusted/checkpoint-policies.sqlite \
  --rotation approved-rotation.json --signed-policy next-policy.json
```

Ordinary policy updates use the same command without `--rotation`. An exact retry
of the last rotation and its accepted policy returns `UNCHANGED`; differing
content at an accepted revision fails. A policy update after a rotation also
uses the new root's quorum. The former issuer group cannot independently regain
authority or fork from an earlier root. Conflicting concurrent rotations cannot
both activate from the same predecessor.

## Verification and expiry recovery

Use the independent starting anchor throughout the lifetime of the store:

```bash
python verify_case_v17.py --zip case.zip --export-public-key /trusted/export.pub.pem \
  --checkpoint-policy-store /trusted/checkpoint-policies.sqlite \
  --policy-root-anchor /trusted/root-anchor.json --require-authenticated-key-policy \
  --minimum-root-version 2 --minimum-policy-revision 2 --format json
```

Configure minimum versions only when established through an independent trusted
record. Export and replay support the same options. `--policy-root-anchor` and
`--policy-issuer-trust` are mutually exclusive. A version 2 store cannot fall
back to direct issuer trust or the legacy update command. Explicit empty trust
paths fail instead of disabling the requested control.

The active root and policy must each satisfy `issued_at <= system UTC < expires_at`.
Caller-supplied case evaluation time cannot backdate these authentication checks.
Old root expiry does not invalidate its authority to approve a valid immediate
successor; only the active root must be current. Expired predecessors remain
cryptographically checked during chain reconstruction. A fresh, fully approved
rotation and higher policy revision can therefore recover an expired deployment
without deleting its counter or anchor. An expired policy can also be replaced
by a fresh higher revision under an otherwise current root.

`export-root` can authenticate and export an expired root for recovery. It reports
`current_by_system_clock` and `policy_acceptance_checked: false`; that result is
not permission to use the current policy. `show` and case verification require
both current root and policy validity and fail when either is stale.

## Reports, API, and operating limits

Authentication reports add `issuer_root` with schema
`ai-dfir/checkpoint-policy-root-verification/v1.7`. It records the anchor and
current root digests, version, chain digest, number of verified rotations, root
acceptance/evaluation/expiry times, and the latest previous/replacement approval
identities and counts. Root or policy failures block required reconstruction and
export before replacing a destination. Evidence integrity and TSA results remain
separate; valid governance cannot rescue their failures or current key revocation.

Python APIs include `validate_root`, `load_root`, `sign_root_rotation`,
`cosign_root_rotation`, `verify_root_rotation`, `initialize_governed_store`,
`migrate_governed_store`, `accept_governed_update`, `load_governed_store`, and
`inspect_governed_root`. Rotation verification checks continuity/signatures;
store acceptance additionally checks the active root, current policy, and
revision. Case APIs add `policy_root_anchor` and `minimum_root_version`.

The CLI exits 0 for success, 1 for rejected authority/state, 2 for argument errors,
and 3 for file/configuration errors. All commands are offline. Root expiry and
issuance are signed claims evaluated against the system clock, not trusted
historical approval timestamps. Distinct keys do not prove distinct human
custodians; compromise of enough current issuer keys can still authorize a
malicious successor. This profile adds no independent TSA, HSM, or human review
service and does not establish historical checkpoint-key authorization.

Protect both database and anchor. Restoring an older whole database is not
detectable without an independently retained root or policy version floor; keep
those floors outside the backup being restored. Retain both when tracking both
kinds of update; a floor detects rollback only below its own value. The store is not a hardware
monotonic counter. Reaching a chain limit requires an independently approved
re-anchoring/recovery process that retains the old audit history and version
floors; there is no automatic history truncation or counter reset.

## Acceptance

The synthetic self-test exercises dual-quorum approval, rejected partial
activation, preserved state, and offline reconstruction after rotation. The 87
focused tests cover full-chain verification, role/domain binding, downgrade and
fork rejection, migration, atomic failure, concurrent updates, expiry recovery,
strict input limits, independent backup floors, embedded-anchor rejection, all
affected CLIs, and composition with evidence and timestamp checks. The full gate
now runs 431 v1.7 tests alongside 111 Evidence Packs and historical compatibility.
Packaging repeats it on extracted committed source and requires this profile's
files and assurance results. Published v1.7.0 package verification keeps its
original contract. No new dependency or licensing change is required.
