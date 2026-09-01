# AI-DFIR v1.7 Release-Candidate Assurance

## Purpose

The v1.7 release-candidate gate is designed to answer a different question from the normal source-tree test suite:

> Does the exact artifact intended for release still contain the reviewed code, required verification material, correct version metadata, and a passing offline-verification implementation after packaging?

The gate therefore validates both the committed source tree and the extracted release ZIP. It does not treat a successful source checkout test as proof that the packaged artifact is equivalent.

## Release chain

```text
reviewed Git commit
      |
      v
git archive HEAD release staging
      |
      +--> generated dependency license inventory
      +--> CycloneDX 1.7 SBOM bound to candidate version
      +--> PACKAGE_MANIFEST_V1.7.json
      |
      v
AI-DFIR-v1.7.x[-rcN].zip / .tar.gz
      |
      +--> exact ZIP extraction
      +--> full release gate from extracted package
      |       +--> 111 Evidence Packs
      |       +--> 19 synthetic detector domains
      |       +--> v1.6 focused compatibility
      |       +--> historical compatibility checks
      |       +--> 56 v1.7 regression tests
      |       +--> v1.7 offline-verification self-test
      |       +--> v1.7 verification-assurance self-test
      |       +--> v1.7 deterministic known-answer self-test
      |
      +--> RELEASE_VALIDATION_V1.7.json
      +--> RELEASE_CANDIDATE_ASSURANCE_V1.7.json
      +--> SHA256SUMS
      |
      v
scripts/verify_release_candidate_v17.py
```

## committed-HEAD-only staging

Release packaging uses `git archive HEAD` as the source-file authority. This is intentional.

An untracked patch, editor backup, locally generated evidence file, credential file, or other working-tree residue must not enter a release archive merely because it exists under the repository directory. The packager copies file bytes from the committed `HEAD` tree and then adds explicitly generated release metadata in an isolated staging directory.

This also prevents the packager from modifying the checked-out source tree when it generates the SBOM, dependency inventory, and package manifest.

## Version handling

The packager accepts stable semantic versions and `-rcN` prerelease versions, for example:

```text
v1.6.0
v1.7.0-rc1
v1.7.0
```

For v1.7 candidates, the versioned release metadata is:

- `PACKAGE_MANIFEST_V1.7.json` using schema `ai-dfir/package-manifest/v1.7`;
- `RELEASE_VALIDATION_V1.7.json` using schema `ai-dfir/release-validation/v1.7`;
- `RELEASE_CANDIDATE_ASSURANCE_V1.7.json` using schema `ai-dfir/release-candidate-assurance/v1.7`;
- `RELEASE_NOTES_V1.7.md`, unless an exact-version notes file exists.

The packager does not fall back to v1.6 release notes for a v1.7 candidate.

A stable v1.7 package is deliberately blocked while `CITATION.cff` still identifies v1.6.0. This prevents a stable v1.7 archive from being published with contradictory stable-version metadata. Use an `-rcN` version during candidate hardening; update stable publication metadata in the final promotion change.

## Package manifest

`PACKAGE_MANIFEST_V1.7.json` records:

- exact candidate version;
- v1.7 release series;
- release-candidate state;
- source Git commit;
- file count;
- Evidence Pack count;
- SHA-256 and size for every packaged file except the manifest itself.

The independent release verifier re-hashes ZIP members and requires the manifest to cover the ZIP exactly, with only the manifest excluded from self-hashing.

## SBOM binding

`SBOM_CYCLONEDX_1.7.json` uses CycloneDX specification version 1.7. The SBOM generator now accepts the AI-DFIR application version separately from the CycloneDX specification version.

For a `v1.7.0-rc1` package, the SBOM application component must report `1.7.0-rc1`. A v1.7 package containing an SBOM that still claims application version `1.6.0` fails release-candidate verification.

## Known-answer verification

`v17_release_candidate_selftest.py` uses synthetic, deterministic Ed25519 keys and fixed investigation timestamps. These keys are test fixtures only and must never be used for production case signing.

The self-test asserts known values for:

- investigation checkpoint hash;
- checkpoint signer key ID;
- outer export public-key SHA-256 fingerprint;
- successful offline case verification;
- signature validity;
- signer trust;
- `network_required = false`.

The package ZIP itself is not claimed to be byte-for-byte reproducible because archive metadata and environment-derived dependency inventory may legitimately differ. The known cryptographic invariants are deterministic.

## Candidate build

```bash
python scripts/release_check.py --full

AI_DFIR_RELEASE_TAG=v1.7.0-rc1 \
python scripts/package_release.py \
  --out-dir /tmp/AI-DFIR-v1.7.0-rc1-release
```

Then independently verify the release directory:

```bash
python scripts/verify_release_candidate_v17.py \
  --release-dir /tmp/AI-DFIR-v1.7.0-rc1-release \
  --version 1.7.0-rc1
```

No network access is required by the v1.7 release verifier.

## SHA-256 coverage

`SHA256SUMS` is generated after release validation and release-candidate assurance metadata. Every packager-owned file in the release directory except `SHA256SUMS` itself must appear exactly once.

The SLSA provenance job runs after packaging and may attach exactly one additional release asset, `multiple.intoto.jsonl`. That provenance sidecar is therefore intentionally outside the packager-generated `SHA256SUMS` boundary. The independent verifier permits only that explicitly named post-packaging asset, requires it to be non-empty valid JSONL, and reports that its SLSA provenance has not been cryptographically verified by the Python release verifier.

Any other unlisted release asset remains a verification failure. Missing checksum entries, duplicate checksum entries, mismatched hashes, malformed provenance JSONL, or arbitrary additional release files also fail closed.

The outer administrative upload bundle is created after `SHA256SUMS` and lives outside the release directory. It is separately hashed in the packager's console result.

## GitHub workflow

For v1.7 tags, `.github/workflows/release.yml` runs the normal full release gate, builds release assets, and then runs `scripts/verify_release_candidate_v17.py` against the packaged release directory before generating SLSA subjects.

After SLSA provenance and release assets are published, the workflow downloads the complete GitHub release surface into a clean directory and runs the verifier again. This second verification checks the actual third-party download surface rather than only the pre-publication staging directory.

Tags matching `v1.7.x-rcN` are treated as prereleases when release metadata is applied. Stable v1.7 promotion remains a separate decision and must not bypass the stable metadata gate.

## Trust boundary

Release assurance proves properties of the AI-DFIR software artifact. It does not transform package-contained case-verification keys into external trust anchors and does not change the case-export trust model.

For actual case evidence, the outer export public key must still be obtained independently of the case ZIP. The deterministic keys used by the release-candidate self-test are synthetic test material only.

## Promotion criteria

Before changing the stable production designation from v1.6.0 to v1.7.0:

1. the release-candidate package gate passes on the intended commit;
2. GitHub CI, CodeQL, dependency review, documentation checks, and production-container checks pass;
3. `CITATION.cff` and other stable version surfaces are updated deliberately;
4. exact v1.7 stable release notes are reviewed;
5. the final tagged package passes the same packaged-artifact gate;
6. checksums, SBOM, license inventory, and SLSA provenance are retained with the release;
7. no administrator bypass is used to skip required repository security policy.
