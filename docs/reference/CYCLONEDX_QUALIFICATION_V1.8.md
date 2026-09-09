# CycloneDX 1.7 Qualification — AI-DFIR v1.8

Status: **development qualification profile**

## Purpose

AI-DFIR v1.8 can project its internal AI/ML-BOM into a CycloneDX 1.7-shaped JSON document. This qualification profile verifies the tested projection with an external CycloneDX validator rather than treating the projection code itself as proof of standards conformance.

The gate validates the exact synthetic projection emitted by `v18_ai_ml_bom.py` and also validates the validator by requiring a deliberately invalid negative-control BOM to fail.

## Validator pin

The qualification workflow uses the stable CycloneDX `sbom-utility` v0.19.2 Linux AMD64 release asset:

- project: `CycloneDX/sbom-utility`
- release: `v0.19.2`
- asset: `sbom-utility-v0.19.2-linux-amd64.tar.gz`
- archive SHA-256: `e0cd37e6e67b1d0e44dbb7b38e055a4e2ee66db590bb8e7f89e2d9b650f4490b`
- target schema: CycloneDX JSON 1.7

The workflow fails if the downloaded archive does not match that digest.

## Offline schema validation

`sbom-utility` ships supported CycloneDX schemas in the validator binary. Before qualification, the harness verifies that the validator exposes CycloneDX 1.7 in its schema inventory.

The actual positive and negative validation commands run inside a separate Linux network namespace using `unshare --net`. This prevents a successful qualification from depending on a remote schema lookup after the validator has been downloaded and checksum-verified.

## Positive control

`scripts/qualify_cyclonedx_v18.py` builds a bounded synthetic internal AI/ML-BOM containing:

- a primary model;
- an embedding model;
- an MCP server;
- a policy component;
- explicit dependency edges.

The internal BOM is projected through `to_cyclonedx_1_7()` and written as `valid-cyclonedx-1.7.json`.

Qualification requires the external validator to return exit code `0` for that projection.

## Negative control

The same projection is copied and deliberately modified so the root CycloneDX `version` is `0`. CycloneDX requires the BOM version to be at least `1`.

The qualification requires `sbom-utility` to reject the negative control with validation-error exit code `2`.

A validator that accepts both files does not qualify the projection.

## Retained evidence

Each qualification run retains:

- `source-ai-ml-bom.json`;
- `valid-cyclonedx-1.7.json`;
- `negative-control-invalid.json`;
- schema inventory output;
- validator stdout/stderr for both controls;
- `qualification-receipt.json`.

GitHub Actions retains the `cyclonedx-v18-qualification` artifact for 14 days.

The receipt binds:

- validator name/version;
- pinned archive SHA-256;
- source internal BOM hash;
- positive and negative fixture hashes;
- validator exit codes;
- validator-output hashes;
- network-isolation observation;
- the final receipt hash.

## Claim boundary

A passing workflow establishes that the **tested AI-DFIR synthetic projection profile** was accepted by the pinned CycloneDX 1.7 validator and that a known-invalid control was rejected.

It does **not** establish that:

- every future or operator-generated BOM automatically conforms;
- an observed inventory is complete;
- component identities or hashes are authentic;
- a production AI deployment has been fully inventoried;
- a valid BOM proves the deployed system is safe;
- CycloneDX validation is equivalent to product certification.

For those reasons, the internal AI/ML-BOM record continues to keep `cyclonedx_conformance_verified` false by default. A deployment or exported BOM should carry its own validation evidence if conformance is asserted for that exact artifact.

## Repository qualification

The qualification path is exercised by:

- `tests/test_v18_cyclonedx_qualification.py` for harness behavior and anti-bypass regressions;
- `.github/workflows/cyclonedx-v18-qualification.yml` for the actual pinned external validator;
- the standard v1.8 workflow, which also executes the qualification-harness regressions.
