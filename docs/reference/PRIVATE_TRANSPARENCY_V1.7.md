# Private transparency-log snapshots and witnessed inclusion

Status: implemented in development, unreleased. This offline profile creates
immutable log snapshots, Ed25519-signed heads, witness co-signatures, SHA-256
inclusion proofs, and consistency proofs against independently retained heads.
It does not operate a network log service or modify case conclusion gates.

## What verification establishes

The verifier requires independently approved trust and its canonical SHA-256 pin,
the expected case identity, and the actual subject bytes (CLI) or independently
known subject digest/size (Python API). A passing inclusion receipt binds that
case/digest/size tuple to a signed tree position under the pinned log key and the
configured number of distinct witness keys. An optional independently supplied
previous head additionally proves that the new tree preserves its entire prefix.

The receipt never supplies its own trust policy or authoritative previous head.
Omitting a prior head required by a receipt fails; a receipt without one reports
`prefix_consistency_verified: false`. An empty prior tree proves only extension
of that empty tree. Repeated subjects are permitted at distinct positions.

Witnesses verify the log signature and, for each nonempty candidate, the complete
state and consistency with an independently retained, fully approved prior head
before signing. A configured threshold of zero is explicitly log-signature-only.
Distinct keys do not prove distinct operators or independent custody. Operators
must retain their accepted heads independently and compare views to detect forks;
the tool cannot prevent a log or witnesses from signing inconsistent views.

`issued_at` is signed, asserted UTC time. Regression from a supplied prior head
fails, but this is not an independent timestamp. Reports explicitly leave
operator independence, trusted time, global fork freedom, provider origin, and
evidence truth unverified. Inclusion does not establish collection completeness,
legal custody, investigative authority, or that any subject content is safe.

## Trust and signed formats

The exact trust object contains:

| Field | Required value |
| --- | --- |
| `schema` | `ai-dfir/private-log-trust/v1.7` |
| `log_id` | A 1–128 character identifier beginning with an ASCII letter/digit, followed by letters/digits or `._:-` |
| `log_key` | Object containing `key_id` and `public_key_hex` |
| `witness_keys` | Ordered array of 0–32 such key objects, distinct from each other and the log key |
| `witness_threshold` | Integer from zero through the configured witness count |

Public keys are exactly 32 raw Ed25519 bytes encoded as lowercase hex. Each key
ID is `sha256:` followed by the full lowercase SHA-256 of those raw public bytes.
The trust pin is SHA-256 of RFC 8785 canonical JSON, including witness array order.
Obtain and approve it through an independent channel; computing a pin from an
untrusted receipt does not establish trust. This profile has no implicit policy
discovery, key rotation, revocation history, or historical authorization claim.

An entry has exactly `schema`, `case_id`, `subject_sha256`, and
`subject_size_bytes`; its schema is `ai-dfir/private-log-entry/v1.7`. A state has
exactly `schema`, `log_id`, `trust_sha256`, and ordered `entries`; its schema is
`ai-dfir/private-log-state/v1.7`. A signed head contains schema
`ai-dfir/private-log-head/v1.7`, log ID, trust pin, tree size, root digest, asserted
time, one log signature, and witness signatures. Every signature binds a canonical
envelope with a fixed signature schema, algorithm, role, key ID, and all head
fields except the signature lists. Signature objects contain only `key_id` and
`signature_hex`. Unknown fields, algorithms, identities, duplicate witness
signatures, and malformed or untrusted extra signatures fail closed.

The private Merkle tree uses the history-tree construction in
[RFC 9162 sections 2.1.1–2.1.4](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1):
empty root `SHA256(empty)`, leaf `SHA256(0x00 || canonical entry)`, and interior
node `SHA256(0x01 || left || right)`. The recursive split is the largest power of
two strictly below the current subtree size. Inclusion and prefix proofs contain
bottom-up sibling hashes; every supplied node must be consumed. These are private
JSON formats, without a claim of CT or Rekor wire-format compatibility.

The inclusion receipt schema is `ai-dfir/private-log-inclusion/v1.7`, with exactly
`subject`, `leaf_index`, `head`, `inclusion_path`, `previous_head_sha256`, and
`consistency_path` in addition to `schema`. Without a prior head, its digest is
null and its consistency path is empty. With one, its canonical digest must match
the independently supplied complete head, including its witness signature list.

## Offline workflow

Provision protected PKCS8 Ed25519 private-key files and approved public trust
separately. The following example assumes one required witness and an independently
approved pin already assigned to `PRIVATE_LOG_TRUST_SHA256`. Commands never prompt
for secrets. Use `--key-password-file` with an encrypted PKCS8 key; key/password
files must be regular non-symlink files, owned by the current user with no
group/other access on POSIX. Each operator retains its own private key.

```bash
python private_transparency_v17.py init \
  --trust trust.json --expected-trust-sha256 "$PRIVATE_LOG_TRUST_SHA256" \
  --private-key log-key.pem --issued-at 2026-09-07T00:00:00Z --out-dir snapshot-0

python private_transparency_v17.py cosign \
  --trust trust.json --expected-trust-sha256 "$PRIVATE_LOG_TRUST_SHA256" \
  --head snapshot-0/head.json --private-key witness-key.pem --out accepted-0.json

python private_transparency_v17.py append \
  --trust trust.json --expected-trust-sha256 "$PRIVATE_LOG_TRUST_SHA256" \
  --state snapshot-0/state.json --previous-head accepted-0.json \
  --subject signed-checkpoint.json --case CASE-001 --private-key log-key.pem \
  --issued-at 2026-09-07T00:01:00Z --out-dir snapshot-1

python private_transparency_v17.py cosign \
  --trust trust.json --expected-trust-sha256 "$PRIVATE_LOG_TRUST_SHA256" \
  --head snapshot-1/head.json --state snapshot-1/state.json \
  --previous-head accepted-0.json --private-key witness-key.pem --out accepted-1.json

python private_transparency_v17.py proof \
  --trust trust.json --expected-trust-sha256 "$PRIVATE_LOG_TRUST_SHA256" \
  --state snapshot-1/state.json --head accepted-1.json --index 0 \
  --previous-head accepted-0.json --out inclusion-1.json

python private_transparency_v17.py verify \
  --trust trust.json --expected-trust-sha256 "$PRIVATE_LOG_TRUST_SHA256" \
  --receipt inclusion-1.json --subject signed-checkpoint.json --case CASE-001 \
  --previous-head accepted-0.json
```

`init`, `append`, or an intermediate `cosign` exits 2 when the configured witness
quorum is still missing. Those commands may have successfully written a draft;
retain it and collect the remaining signatures. Repeat `cosign` with each required
witness, taking the preceding output as the next input. Only a fully approved
head can be appended to, used for a proof, or pass `check-head`. Successful final
operations exit 0, invalid/untrusted/conflicting operations exit 1, and an
interrupted operation exits 130.

Every snapshot is a new mode-0700 directory with private `state.json`, draft
`head.json`, and a final `receipt.json` describing publication and file digests.
That publication receipt is not an inclusion proof. Witnesses create separate
head files; earlier snapshots and receipts remain unchanged. Files use exclusive
creation, so existing outputs are preserved. Incomplete writes cannot publish a
successful snapshot receipt. Keep incomplete directories separate and retry into
a new directory. Filesystem crash recovery, locking between independent writers,
replication, and global head retention remain operator responsibilities.

## Bounds and evidence use

| Input | Limit |
| --- | --- |
| Trust or head JSON | 32 KiB each |
| Inclusion receipt JSON | 128 KiB |
| State JSON | 4 MiB and 4,096 entries |
| Witness keys/signatures | 32 each |
| Inclusion or consistency path | 17 SHA-256 nodes |
| CLI subject bytes | 8 MiB; empty files allowed |
| Entry size assertion | Exact integer, zero through 9,007,199,254,740,991 |
| Private key / password file | 16 KiB / 4 KiB |

Strict UTF-8 JSON rejects duplicate keys, excessive structure, and non-finite
numbers. JSON readers reject symlinks and special files. Entry case IDs use the
same identifier grammar as the log ID. Reports contain digests, counts, status,
and explicit verification limits; they do not print evidence payloads or secrets.

Retain the inclusion receipt, approved trust, its independent pin, accepted prior
head, and verifier output with the subject. They can support the existing
`runtime.transparency_anchor` Evidence Pack as separately reviewed artifacts.
The current recorded-rating gate is not automatically promoted by this command;
there is no new case replay adapter or implicit external-anchor approval.

The legacy `transparency_anchor_v14.py verify-receipt` accepted a recorded
`inclusion_verified` flag without checking an actual log proof. It now always
reports `valid: false`, `inclusion_proof_verified: false`, and a critical unverified
proof finding for that legacy format. `recorded_assertions_match` preserves the
separate assertion comparison. Its CLI exits 1 even when writing a validation
file. Signed submission creation/verification remains available; cryptographic
inclusion requires the new proof profile.

The 160 focused regressions cover independent iterative roots, every leaf/prefix
around power-of-two boundaries, altered/missing/extra paths, signed forks,
subject/policy substitution, witness roles/quorums, bounded state, protected keys,
exclusive/partial output, and the complete offline CLI workflow. Source and
extracted package checks require both the self-test and those regressions. These
are synthetic cryptographic acceptance tests, not an independent operator audit.
