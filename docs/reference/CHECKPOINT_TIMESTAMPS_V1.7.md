# External checkpoint timestamps — unreleased v1.7 profile

This profile prepares RFC 3161 requests and verifies external timestamp receipts
offline. It is implemented in development and is **not included in published
v1.7.0 assets**. No independently operated TSA is deployed or selected by this
code. The acceptance suite uses an ephemeral synthetic authority.

## Proposition and trust boundary

A timestamp authority (TSA) signs an attestation that a particular hash existed
at its stated time. Its clock, accuracy, operation, and certificate trust matter
to that interpretation. The protocol does not establish the truth of the hashed
content. See [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161).

AI-DFIR binds the timestamp to the entire signed ledger checkpoint and tenant/
case identity. It requires an independently approved CA bundle **and** the
SHA-256 fingerprint of the approved TSA signing certificate. Embedded
certificates only help build a chain; they cannot supply trust. System CA stores
cannot broaden the explicitly supplied trust set.

A passing receipt means the configured authority cryptographically attests to
the checkpoint statement's existence at its reported time, subject to its
accuracy. It does not prove that the checkpoint's claimed `signed_at` is the
actual signing instant. It also does not establish investigator identity, source
truth, ledger completeness beyond the checkpoint, or an independent operator's
governance. Verify the case to check its ledger and evidence as well.

Current checkpoint key policy remains a separate requirement. A timestamp never
reactivates a retired/revoked key. Historical authorization needs a defined
historical policy and preserved revocation evidence; this profile does not
implement that decision.

The separate [historical key-trust record profile](CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md)
uses a distinct timestamp statement to bind retained issuer-approved policy and
decision inputs, then reproduces that result throughout the signed accuracy
interval. It does not establish complete historical revocation/custody evidence
or replace current case authorization. Receipts for these two statement schemas
are not interchangeable.

## Bound statement and request

The local statement is RFC 8785 canonical JSON with these exact fields:

| Field | Value |
|---|---|
| `schema` | `ai-dfir/checkpoint-timestamp-statement/v1.7` |
| `tenant_id`, `case_id` | Explicit case scope; case must match the checkpoint |
| `checkpoint_sha256` | The v1.7 ledger checkpoint hash |
| `signed_checkpoint_sha256` | SHA-256 of canonical `SignedLedgerCheckpoint.to_dict()` |

The second hash includes the signature, public key, key identifier, claimed
signing time, and checkpoint. Re-signing the same ledger with another key cannot
reuse its receipt. Changing tenant identity also changes the statement.

Only SHA-256 of this statement goes into the RFC 3161 message imprint. Requests
also carry a fresh 128-bit nonce, the certificate-request flag, and an optional
numeric TSA policy OID. They contain no evidence bytes, case names, private keys,
or signed-checkpoint body. A hash can still be correlatable; submission remains
an explicit operator action. Request generation does not authenticate the TSA.

## Prepare, obtain, and retain a receipt

Install the default Python requirements and a maintained OpenSSL 3 executable.
`asn1crypto` provides structured ASN.1 decoding; OpenSSL verifies signatures,
certificate chains, and RFC 3161 request binding. The supported runtime is
OpenSSL 3, with a timestamp-only certificate purpose and authentication level 2.
See [OpenSSL timestamp verification](https://docs.openssl.org/3.0/man1/openssl-ts/).

1. Obtain the TSA's approved CA chain and signing-certificate fingerprint through
   a trusted administrative channel. Pin the **DER certificate's SHA-256**, not
   the PEM file hash or a certificate discovered in an unverified receipt.
2. Prepare a request using the same signed checkpoint that the case will export:

   ```bash
   python checkpoint_timestamp_v17.py prepare \
     --signed-checkpoint signed_checkpoint.json \
     --tenant TENANT-1 --case CASE-1 --out checkpoint.tsq
   ```

   Add `--tsa-policy-oid <approved-numeric-oid>` when the authority requires a
   specific timestamp policy. Save the reported `request_sha256` independently
   with the submission record. Existing output files are never overwritten.
3. Use the approved TSA's documented submission procedure to send
   `checkpoint.tsq` and save its RFC 3161 response as `checkpoint.tsr`. For HTTP
   services, the protocol uses `application/timestamp-query` and
   `application/timestamp-reply`. This CLI performs no network submission and
   provides no built-in authority credentials or endpoint.
4. Retain the exact request, response, approved trust material, request digest,
   and verification report with the case records. The receipt is an external
   sidecar to the case ZIP, avoiding a circular hash dependency.

## Verify the case or reconstruct it

```bash
python verify_case_v17.py \
  --zip case.zip --export-public-key /trusted/export-public.pem \
  --tenant TENANT-1 --case CASE-1 \
  --timestamp-request checkpoint.tsq --timestamp-response checkpoint.tsr \
  --tsa-ca-file /trusted/tsa-ca.pem \
  --expected-tsa-certificate-sha256 <approved-64-lowercase-hex> \
  --expected-timestamp-request-sha256 <retained-request-sha256> \
  --require-checkpoint-timestamp --format json
```

The same six timestamp options work with `case_export_v17.py create`,
`case_export_v17.py verify`, and `replay_case_v17.py`. They compose with the
external checkpoint key-policy options. Export checks the receipt before
staging or writing its destination. Reconstruction proceeds only after all
case, key-policy, and configured timestamp controls pass.

For a standalone receipt check, use `checkpoint_timestamp_v17.py verify` with
`--signed-checkpoint`, `--tenant`, `--case`, and the timestamp options. Standalone
verification always requires the receipt and TSA trust inputs; it verifies the
signed checkpoint statement, not the full case ZIP or ledger history.

The Python API is `evaluate_checkpoint_timestamp()`. Both `export_case()` and
`verify_case()` accept these additional keyword arguments:

| Argument | Meaning |
|---|---|
| `timestamp_request`, `timestamp_response` | Retained request/response bytes |
| `tsa_ca_pem` | Verifier-controlled PEM certificate bundle bytes |
| `expected_tsa_certificate_sha256` | Mandatory approved TSA certificate pin |
| `expected_timestamp_request_sha256` | Optional pin of the originally prepared request |
| `require_checkpoint_timestamp` | Fail if timestamp inputs are absent |

Input files are read into bounded byte snapshots before use. No archive path,
receipt field, shell command, or module reference supplies an executable or
authority trust location. The OpenSSL executable comes from the trusted runtime.

## Report and failure behavior

| Result | Interpretation |
|---|---|
| `NOT_CONFIGURED` | No timestamp options and no requirement; existing behavior preserved |
| `NOT_RUN` | Case parsing/integrity stopped before the timestamp stage |
| `FAIL` | Required input missing, unsupported/malformed data, mismatch, or failed crypto/trust |
| `PASS` | Request, checkpoint, nonce, certificate pin, signature, and chain checks passed |

Any supplied timestamp setting activates verification even without the
requirement flag. Partial configuration cannot silently become optional.
Receipts or CA files placed inside the ZIP do not satisfy external inputs.

Successful reports preserve statement/request/response/CA-bundle digests, the
TSA certificate fingerprint, policy OID, serial, authenticated `tsa_gen_time`,
accuracy if supplied, and the verifier's system UTC evaluation time. A missing
accuracy is reported as unknown, not zero. Failed receipts never populate
authenticated time or assert checkpoint existence.

`checkpoint_timestamp` is separate from `signature_valid`, `signer_trusted`,
and `checkpoint_key_policy`. Timestamp failure makes combined verification fail
and blocks reconstruction. A passing receipt cannot repair modified evidence,
an untrusted export manifest, or a revoked checkpoint key.

Verification failures return exit 1. Malformed case archives retain the existing
exit 2 contract. Unreadable/oversized input files or refused export/preparation
return configuration/runtime error exit 3. A receipt rejected by the verifier
returns `FAIL`/exit 1, including unavailable OpenSSL. Successful preparation is
`PREPARED`/exit 0; it is not an external timestamp assurance result.

## Supported bounds and limitations

- Requests: 4 KiB, canonical profile encoding, SHA-256 imprint, 128-bit nonce,
  certificate request, no extensions. Responses: 1 MiB, complete ASN.1 object,
  one CMS signer, at most 16 certificates, no unsupported timestamp extensions.
  Trailing bytes are rejected. Response certificate SET order is preserved for
  OpenSSL interoperability; signed CMS bytes are never rewritten for verification.
- CA bundles: 256 KiB, at most 16 PEM certificates, no other material. CMS
  signature digests must be SHA-256/384/512. A CA-authorized signing certificate
  must have the exclusive critical timestamp EKU accepted by OpenSSL.
- Certificate-chain validity is checked at the verifier's current clock. The
  token time must fall within its leaf certificate's validity and cannot exceed
  that clock by more than five minutes. The tolerance is not timestamp accuracy.
  No backdated certificate-verification option is exposed by this profile.
- `tsa_revocation` is `NOT_CHECKED`. The verifier does not fetch CRLs, OCSP,
  AIA certificates, or replacement policy. Supply a currently approved trust
  configuration; archived validation and timestamp renewal remain future work.
- `tsa_operator_independence` is `NOT_ASSESSED`. A locally operated or synthetic
  authority can pass cryptographic verification when deliberately trusted. Such
  a result is not evidence that the operator or clock is independent.
- Pinning the retained request detects replacement by another request/receipt
  pair. Repeating offline verification of the same valid receipt is allowed;
  this is not a stateful one-use nonce service or a proof of recent submission.
- This is an RFC 3161 timestamp profile, not a transparency-log inclusion or
  consistency proof. It does not promote the older v1.4 receipt JSON checks into
  cryptographic external anchoring. No `inclusion_verified` flag is trusted.

## Acceptance and dependency review

`v17_timestamp_selftest.py` creates temporary CA/TSA keys and invokes OpenSSL to
issue a real protocol response. The 68-test regression suite includes corrupted
signatures and correctly signed negative cases, independent trust failures,
request replay/substitution, bounded parsing, and all case/standalone CLIs.
The quick/full and extracted-package gates enforce this coverage. Evidence Pack
coverage remains 111; this investigation-assurance profile adds no new detector.

`asn1crypto>=1.5.1,<2` is a new default Python dependency under MIT; see its
[upstream project and license](https://github.com/wbond/asn1crypto). OpenSSL 3 is
an operator-installed executable. No private signing keys, real evidence,
external credentials, or timestamp service accounts are shipped. Independent
security review is required before production adoption.
