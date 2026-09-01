# AI-DFIR v1.7 — Investigation Integrity & Offline Verification

> **Release status:** v1.7.0 is the stable investigation-integrity and offline-verification release line. Stable promotion follows successful RC2 release assurance and independent verification of the final published GitHub release surface.

v1.7 adds an investigation-integrity and independent-verification layer without replacing the v1.5 signed case-export trust model.

## Added

- append-only investigation ledgers with RFC 8785 canonicalization and SHA-256 hash chaining;
- deterministic investigation checkpoints and Ed25519 checkpoint signatures;
- explicit separation of cryptographic signature validity from signer trust;
- v1.5-compatible exports containing manifest-bound v1.7 ledger, checkpoint, signed-checkpoint, and trust-store state;
- offline verification of exported artifacts, ledger integrity, checkpoint binding, checkpoint signatures, and signer trust;
- hostile ZIP protections and bounded verification resource limits;
- independent `verify_case_v17.py` text/JSON verification workflow with exit codes `0/1/2/3`;
- detached-working-directory and network-guard assurance testing;
- documented third-party trust model and verification procedure;
- committed-HEAD-only release staging so untracked local files cannot silently enter a release archive;
- version-aware v1.7 package manifest, release-validation, and release-candidate assurance metadata;
- source-commit binding for packaged release content;
- CycloneDX 1.7 SBOM application-version binding;
- deterministic release known-answer verification;
- clean-room extracted-package enforcement of all 56 v1.7 regression tests.

## Compatibility

The outer export manifest remains `ai-dfir/case-export-manifest/v1.5`. Existing v1.5 packages remain valid v1.5 exports. A v1.7 verifier requires the additional manifest-bound v1.7 verification state and reports a v1.5-only package as unsupported for v1.7 verification rather than treating it as v1.7-valid.

Historical v1.6, v1.5, v1.4, v1.3, v1.2, and v1.1 compatibility checks remain part of the full release gate under current semantics.

## Trust boundary

A v1.7 case package does not establish its own outer trust anchor. The reviewer must obtain the export public key independently. Package-contained checkpoint public keys are public verification material; their trust is meaningful because the checkpoint trust store is covered by the externally verified v1.5 export manifest.

A valid checkpoint signature is not sufficient by itself. The signer must also be trusted.

## Release packaging boundary

Stable v1.7 packaging requires the published version metadata in `CITATION.cff` to match the exact stable release version. The packager fails closed if required v1.7 release inputs are missing or stable publication metadata is inconsistent.

The v1.7 release gate verifies the actual packaged ZIP, its package manifest, SBOM application version, source commit, `SHA256SUMS`, release-validation report, and release-assurance report. The GitHub release workflow also verifies the complete published release surface after SLSA provenance is attached. Passing source-tree tests alone is not considered sufficient release evidence.

## Important boundary

Offline verification establishes the integrity and trust relationships represented by the signed package and supplied trust anchor. It does not prove that the original evidence source was truthful, that collection was complete, or that an analyst's attribution or causal conclusion is correct.
