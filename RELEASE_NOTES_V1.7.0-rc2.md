# AI-DFIR v1.7.0-rc2 - Published Release Verification

RC2 closes a release-assurance boundary discovered during independent verification of the published `v1.7.0-rc1` GitHub release.

## Fixed

- distinguishes packager-owned checksum assets from the SLSA provenance sidecar added after packaging;
- permits only the known `multiple.intoto.jsonl` post-packaging provenance asset;
- rejects arbitrary additional unlisted release files;
- requires the SLSA sidecar to be non-empty valid JSONL;
- explicitly reports that the Python verifier does not cryptographically verify SLSA provenance;
- re-downloads and verifies the complete published GitHub release surface after release assets and provenance are uploaded.

## Preserved assurance

- committed-HEAD-only package staging;
- exact package-manifest coverage;
- source-commit binding;
- 56 v1.7 regression tests;
- 111 Evidence Packs;
- deterministic release-candidate known-answer verification;
- offline case-package verification;
- explicit separation of signature validity from signer trust.

## Trust boundary

`SHA256SUMS` covers the packager-produced release assets. `multiple.intoto.jsonl` is created by the SLSA provenance job after the package checksum set exists and is therefore separately scoped.

Its presence and basic JSONL structure are checked by the AI-DFIR release verifier, but cryptographic SLSA provenance verification remains a separate operation. The verifier reports this limitation explicitly rather than treating structural validation as cryptographic verification.

Stable production metadata remains v1.6.0. RC2 does not promote v1.7 to stable.
