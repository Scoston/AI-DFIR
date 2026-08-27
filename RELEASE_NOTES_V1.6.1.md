# AI-DFIR v1.6.1 - Release and Supply-Chain Hardening

v1.6.1 is a hardening release built on v1.6.0. It focuses on production dependency reproducibility, CI enforcement, container security, release integrity, and build efficiency.

## Hardening changes

- isolated the production gateway dependency profile from model/GPU and optional cloud runtimes;
- added a hash-pinned production gateway dependency lock;
- pinned GitHub Actions and reusable workflows to immutable commit SHAs;
- extended immutable-action enforcement to repository-local composite actions;
- added a required production-container validation gate;
- verified non-root execution as UID 10001;
- added CI enforcement for production ownership and group/other write permissions;
- assigned application ownership during Docker COPY;
- removed the redundant recursive production chmod after validating the resulting permission invariant;
- reduced the local uncached production-container build from approximately 304 seconds to 55 seconds;
- reduced the quick CI dependency footprint while retaining scheduled/manual full regression;
- made release archive identity, release titles, release-note selection, and SLSA subject generation derive from the release tag.

## Evidence Packs

Total catalog remains **111**.

## Release integrity

v1.6.1 release archives are generated from the release tag and validated through the full release gate and clean-room extracted-archive regression.

Release artifacts include checksums, SBOM data, dependency-license inventory, package-manifest data, and SLSA provenance.

Production container promotion remains subject to the digest-pinned base image, required production-container validation, immutable GitHub Action references, and the signed container workflow.

## Compatibility

This patch preserves the v1.6 investigation model and Evidence Pack catalog while strengthening the build, release, and production-assurance path.

## v1.6.0 preservation

The existing v1.6.0 tag and published artifacts remain unchanged.
