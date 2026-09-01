# AI-DFIR v1.7.0 - Investigation Integrity & Offline Verification

AI-DFIR v1.7.0 promotes the v1.7 investigation-integrity and offline-verification line to stable after successful RC2 release assurance and independent verification of the final published GitHub release surface.

## Major capabilities

- append-only investigation-ledger integrity with deterministic checkpoint hashing;
- Ed25519-signed investigation checkpoints;
- explicit separation of cryptographic signature validity from signer trust;
- v1.5-compatible case exports carrying manifest-bound v1.7 verification state;
- offline artifact, ledger, checkpoint, signature, and trust verification;
- hostile ZIP protections and bounded verification resource limits;
- third-party verification CLI with machine-readable reports and explicit exit codes;
- committed-HEAD-only release packaging;
- package-manifest and source-commit binding;
- CycloneDX application-version binding;
- deterministic release known-answer verification;
- 56 v1.7 regression tests;
- 111 Evidence Packs;
- post-publication verification of the complete GitHub release surface.

## Published-release trust boundary

Packager-generated `SHA256SUMS` covers the packager-owned release assets. GitHub's SLSA workflow publishes `multiple.intoto.jsonl` afterward as a separately scoped provenance asset.

The AI-DFIR release verifier permits only that exact external filename, requires it to be non-empty valid JSONL, and rejects arbitrary additional unlisted release assets.

The Python release verifier reports SLSA provenance presence but does not claim cryptographic verification of the SLSA provenance itself.

## Compatibility

v1.7 extends the v1.5 signed case-export architecture rather than replacing it. A v1.5-only export remains valid as a v1.5 package but does not satisfy v1.7 offline-verification requirements.

## Release assurance

Stable promotion follows successful v1.7.0-rc2 validation of:

- the full release gate;
- all 56 v1.7 regression tests;
- all 111 Evidence Packs;
- committed-source package construction;
- extracted-package verification;
- source-commit binding;
- independent SHA-256 validation;
- SLSA provenance publication;
- post-publication GitHub workflow verification;
- independent download and offline verification of the complete published RC2 release.

A successful software release does not by itself certify any specific enterprise deployment as production-ready.
