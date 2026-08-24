# GitHub Production Guide for AI-DFIR v1.6

The repository includes CI, CodeQL, Dependency Review, OpenSSF Scorecard, full
regression, SLSA release provenance, container build/signing, Dependabot,
CODEOWNERS, issue templates and PR templates.

## Repository settings

For a production repository:

- protect `main` and release branches;
- require pull requests and CODEOWNERS review;
- require at least two approvals for trust-boundary code;
- require CI, CodeQL and dependency-review checks;
- enable GitHub secret scanning and push protection;
- enable Dependabot alerts and dependency graph;
- disable force pushes/deletion on protected branches;
- restrict Actions to an organization allowlist;
- pin third-party Actions to reviewed commit SHAs if your organization requires
  stronger supply-chain assurance than major-version tags;
- use a protected `release` GitHub Environment for publish jobs;
- require immutable production image digests;
- publish SHA-256, SBOM and SLSA provenance for each release.

## Current workflow baselines

The provided 2026 workflow examples use:

- `actions/checkout@v7`
- `actions/setup-python@v7`
- `actions/dependency-review-action@v5`
- `github/codeql-action@v4`
- `docker/setup-buildx-action@v4`
- `docker/login-action@v4`
- `docker/build-push-action@v7`
- `sigstore/cosign-installer@v4.1.2`
- `slsa-framework/slsa-github-generator ... @v2.1.0`

Dependabot should keep those baselines current.

## Tag release flow

```text
protected source
  -> full regression
  -> exact release archives
  -> checksums + SBOM
  -> SLSA provenance
  -> GitHub release
  -> production image build
  -> image SBOM/provenance
  -> keyless Cosign signature
  -> admission by immutable digest
```

## Do not store

Never store production credentials, customer evidence, private signing keys,
bearer tokens, exported case data or real incident prompts in the public
repository or GitHub Actions artifacts.
