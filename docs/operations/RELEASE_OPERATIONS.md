# Release Operations

Only publish artifacts created by `scripts/package_release.py`. Verify `SHA256SUMS`, `RELEASE_VALIDATION_V1.5.json`, SBOM, dependency license inventory, package manifest, LICENSE, NOTICE and release notes. Attach the source ZIP/TAR.GZ and validation assets to GitHub Releases. Do not publish a package if the extracted-ZIP full release check did not pass.
