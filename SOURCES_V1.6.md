# AI-DFIR v1.6 Production / Supply-Chain Sources

Verified 2026-08-24.

- GitHub Actions checkout: https://github.com/actions/checkout
- GitHub setup-python: https://github.com/actions/setup-python
- GitHub Dependency Review: https://github.com/actions/dependency-review-action
- SLSA GitHub Generator: https://github.com/slsa-framework/slsa-github-generator
- Sigstore Cosign installer: https://github.com/sigstore/cosign-installer
- Docker Build Push Action: https://github.com/docker/build-push-action
- Docker Buildx Action: https://github.com/docker/setup-buildx-action
- SPIFFE/SPIRE concepts: https://spiffe.io/docs/latest/spire-about/spire-concepts/
- PostgreSQL High Availability: https://www.postgresql.org/docs/current/high-availability.html
- Sigstore security/transparency: https://docs.sigstore.dev/about/security/
- SLSA provenance specification: https://slsa.dev/spec/v1.2/provenance

The GitHub workflow examples are intended as current secure defaults, not permanent pins. Dependabot and organizational action allowlists should keep them current; high-assurance environments should pin third-party actions to reviewed immutable commit SHAs.
