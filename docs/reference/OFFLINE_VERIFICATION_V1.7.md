# AI-DFIR v1.7 Offline Case Verification

## Purpose

AI-DFIR v1.7 extends the v1.5 signed case-export ZIP format with an investigation ledger, checkpoint, signed checkpoint, and checkpoint-signer trust state that can be verified without network access.

The assurance goal is not merely that AI-DFIR can reopen its own export. The goal is that a separate reviewer can receive the exported ZIP and an independently obtained export public key, run the verifier from a detached working directory, and produce a durable verification report.

## Trust model

A v1.7 verification decision has two trust layers.

1. **Export trust anchor.** The reviewer supplies the v1.5 export public key independently of the package. That key verifies `CASE_EXPORT_MANIFEST.signed.json`, which binds the exported files and the v1.7 verification metadata.
2. **Checkpoint signer trust.** The manifest-bound v1.7 trust store identifies checkpoint public keys that are trusted for the investigation checkpoint. The checkpoint signature must be cryptographically valid and its signer must also be trusted.

A valid signature is not the same thing as a trusted signer. The verifier reports those states separately.

The package is not self-trusting. A public key copied from inside the package is not a substitute for the independently obtained export public key.

## Package verification chain

```text
independently obtained export public key
        |
        v
CASE_EXPORT_MANIFEST.signed.json
        |
        +--> SHA-256 + size for exported case artifacts
        |
        +--> 00_case/v17/investigation_ledger.jsonl
        +--> 00_case/v17/checkpoint.json
        +--> 00_case/v17/signed_checkpoint.json
        +--> 00_case/v17/trusted_signers.json
                         |
                         v
          checkpoint signature validity
                         +
                 checkpoint signer trust
```

## Recommended third-party command

Human-readable report:

```bash
python verify_case_v17.py \
  --zip CASE-001.zip \
  --export-public-key export.pub.pem \
  --tenant TENANT-001 \
  --case CASE-001 \
  --format text \
  --out CASE-001.verification.txt
```

Machine-readable report:

```bash
python verify_case_v17.py \
  --zip CASE-001.zip \
  --export-public-key export.pub.pem \
  --tenant TENANT-001 \
  --case CASE-001 \
  --format json \
  --out CASE-001.verification.json
```

Verification does not require access to GitHub, a cloud provider, the originating workstation, or the original case directory.

## Exit-code contract

| Exit | Meaning |
|---:|---|
| `0` | Verification passed. |
| `1` | Verification completed but integrity, identity, signature, or trust validation failed. |
| `2` | Package is malformed or unsupported for v1.7 offline verification. |
| `3` | Runtime or configuration error prevented a verification decision. |

Automation should use the exit code and the machine-readable report together. A nonzero code must not be converted into a successful verification result by a wrapper or orchestration layer.

## Report interpretation

A valid package should report all of the following:

- `package_safety = PASS`
- `export_manifest_integrity = PASS`
- `artifact_integrity = PASS`
- `ledger_integrity = PASS`
- `checkpoint_integrity = PASS`
- `signature_valid = true`
- `signer_trusted = true`
- `combined_checkpoint_verification = true`
- `network_required = false`
- `valid = true`

Important failure distinctions:

- **Wrong export trust anchor:** the outer export signature fails and artifact integrity is `NOT_TRUSTED`; checkpoint trust is not enough to rescue the package.
- **Tampered artifact:** the signed manifest remains the reference and the artifact hash or size fails.
- **Tampered ledger:** the outer manifest may still be valid in a deliberately re-signed negative fixture, but the ledger chain fails.
- **Invalid checkpoint signature:** `signature_valid = false`.
- **Valid signature from an untrusted signer:** `signature_valid = true` while `signer_trusted = false`; the overall verification still fails.
- **Plain v1.5 package:** classified as unsupported for v1.7 offline verification rather than silently treated as v1.7-valid.
- **Malformed or hostile ZIP:** rejected before normal content verification when archive-safety checks fail.

## Hostile-input protections

The verifier rejects or bounds:

- path traversal and absolute paths;
- Windows drive paths and backslash-based member names;
- duplicate members;
- directory and symbolic-link members;
- excessive member counts;
- excessive total uncompressed size;
- excessive per-member uncompressed size;
- suspicious compression ratios;
- oversized verification metadata;
- malformed JSON, malformed ledger rows, and unsupported schemas.

The defaults are defensive limits, not claims about the maximum size of legitimate forensic evidence. The assurance CLI exposes explicit overrides for authorized larger cases.

## Public verification material is not secret material

The v1.7 package intentionally stores checkpoint public keys, key identifiers, signatures, timestamps, and signed checkpoint metadata in clear text. These values are verification material and are not private signing keys, credentials, tokens, or secrets.

Private signing keys must never be placed in the case ZIP or verification report.

## Independent-review procedure

A reviewer should record:

1. how the exported ZIP was obtained;
2. the ZIP SHA-256 reported by the verifier;
3. how the export public key was obtained independently;
4. the expected tenant and case identifiers, when known;
5. the verifier version or source commit used;
6. the command executed;
7. the process exit code;
8. the complete JSON or text verification report;
9. any resource-limit overrides used;
10. the disposition of every finding when verification does not pass.

The report should be retained with the review record rather than replacing the original exported package.

## Assurance tests

Run the focused assurance suite:

```bash
python -m pytest tests/test_v17_verification_assurance.py -q
```

Run the detached/offline assurance self-test:

```bash
python v17_verification_assurance_selftest.py
```

The self-test runs the verifier from a detached working directory with a Python network guard and validates exit codes `0`, `1`, `2`, and `3`.

## Boundary

Offline verification proves the integrity and trust relationships represented by the signed package and supplied trust anchor. It does not prove that the original evidence source was truthful, that acquisition was complete, that an organization retained every relevant log, or that an analyst's causal or attribution conclusion is correct.
