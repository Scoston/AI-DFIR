# AI-DFIR v1.7 — Investigation Integrity & Offline Verification

v1.7 is the stable investigation-integrity and offline-verification layer. It extends the v1.5 signed case-export format rather than replacing it.

## Added

- append-only investigation ledger integrity with deterministic checkpoint hashing;
- Ed25519-signed investigation checkpoints;
- explicit separation of signature validity from signer trust;
- v1.5-compatible case exports containing manifest-bound v1.7 verification state;
- offline artifact, ledger, checkpoint, signature, and trust verification;
- hostile ZIP protections and bounded verification resource limits;
- third-party assurance CLI with text and JSON reports;
- explicit verifier exit-code contract for automation;
- detached-working-directory and network-guard assurance testing;
- documented independent-review workflow and trust-boundary interpretation;
- committed-HEAD-only release staging that excludes untracked working-tree residue;
- version-aware v1.7 package manifests and release-validation reports;
- packaged-artifact SHA-256 coverage and source-commit binding;
- CycloneDX application-version binding for release candidates;
- deterministic release-candidate known-answer verification;
- extracted-package enforcement of all 56 v1.7 regression tests;
- dedicated v1.7 release-candidate assurance verification;
- published-release verification that permits only the known post-packaging SLSA provenance sidecar while rejecting arbitrary extra assets;
- clean re-download and verification of the final GitHub release surface after publication.

## Compatibility

The outer case-export manifest remains `ai-dfir/case-export-manifest/v1.5`. A v1.7 verifier requires the additional manifest-bound v1.7 ledger/checkpoint/trust members. A v1.5-only package remains a valid v1.5 export but is reported as unsupported for v1.7 offline verification.

## Trust boundary

The exported package does not establish its own outer trust anchor. A reviewer must obtain the export public key independently. Package-contained checkpoint public keys are public verification material whose trust is meaningful because the v1.7 trust store is covered by the externally verified v1.5 manifest.

## Release status

v1.7.0 is the stable release of the investigation-integrity and offline-verification line. Stable promotion follows successful v1.7.0-rc2 validation of committed-source packaging, offline verification, release assurance, SLSA provenance separation, and independent verification of the final published GitHub release surface.
