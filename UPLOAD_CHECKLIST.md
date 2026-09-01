# GitHub Upload Checklist - AI-DFIR Releases

## Repository preparation

1. Create the target GitHub repository **without** auto-generating another README or license.
2. Upload the contents of the **versioned AI-DFIR source archive**, not the outer administrative upload bundle.
3. Keep `.github/CODEOWNERS.example` as a template until the real maintainer user/team is known. Copy it to `.github/CODEOWNERS` only after replacing every example owner.
4. Configure branch protection/rulesets for `main`, required review, and required status checks.
5. Enable Private Vulnerability Reporting, secret scanning/push protection, the dependency graph, Dependabot, CodeQL, and dependency review where available.
6. Set GitHub variable `AI_DFIR_PYTHON_BASE_IMAGE_DIGEST` to a reviewed digest-pinned Python base image reference before enabling the production container workflow.
7. Configure protected release environments/approvers if required by organization policy.
8. Review GitHub Actions permissions and, where required by policy, pin third-party actions to reviewed commit SHAs.
9. Merge through normal review; do not upload real incident evidence, credentials, private keys, provider tokens, or customer data.
10. Tag the intended semantic release version. The release workflow should run the full release gate, build release assets, produce SLSA provenance, and publish assets.
11. The container workflow should build from the immutable base reference and sign the pushed digest with Cosign.
12. Verify release checksums, SBOM, license inventory, and provenance before promotion.
13. Run deployment-specific `production_readiness_v16.py`; GitHub release success does not make a particular deployment production-ready.

## Required repository files

- `README.md`
- `LICENSE` / `NOTICE` / `LICENSE_GUIDE.md` / `THIRD_PARTY_NOTICES.md`
- `SECURITY.md` / `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` / `SUPPORT.md` / `GOVERNANCE.md`
- `ROADMAP.md` / `CITATION.cff` / `AUTHORS.md`
- `THREAT_MODEL.md` / `DATA_HANDLING.md`
- `INSTALL.md` / `TESTING.md` / `V1.6_RUNBOOK.md`
- `RELEASE_CHECKLIST.md`
- `.github/ISSUE_TEMPLATE/*`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/dependabot.yml`
- `.github/workflows/*`

## Build release assets locally

```bash
python scripts/release_check.py --full
RELEASE_TAG=vX.Y.Z
AI_DFIR_RELEASE_TAG="$RELEASE_TAG" python scripts/package_release.py --out-dir "/tmp/AI-DFIR-${RELEASE_TAG}-release"
```

The packager performs an exact-archive clean-room regression.

## Expected release assets

- `AI-DFIR-vX.Y.Z.zip`
- `AI-DFIR-vX.Y.Z.tar.gz`
- `AI-DFIR-vX.Y.Z-Documentation.zip`
- `AI-DFIR-vX.Y.Z-Test-Corpus.zip`
- `AI-DFIR-vX.Y.Z-demo.mp4` when an exact-version demo exists
- `SHA256SUMS`
- `SOURCE_RELEASE_CHECK.json`
- `EXTRACTED_RELEASE_CHECK.json`
- `RELEASE_VALIDATION_V1.6.json`
- `PACKAGE_MANIFEST_V1.6.json`
- `SBOM_CYCLONEDX_1.7.json`
- `DEPENDENCY_LICENSE_INVENTORY.json`
- `LICENSE` / `NOTICE`
- `RELEASE_NOTES_VX.Y.Z.md` or the documented series fallback

## Final publish gate

- [ ] Source-tree full release gate PASS
- [ ] Exact release ZIP extracted and full release gate PASS
- [ ] `SHA256SUMS` verified
- [ ] Secret scan PASS
- [ ] complete Evidence Pack matrix PASS
- [ ] **19/19 high-fidelity synthetic detector domains PASS**
- [ ] v1.6 focused suite PASS
- [ ] v1.5/v1.4/v1.3/v1.2/v1.1 compatibility PASS under current semantics
- [ ] Workbench JavaScript syntax PASS
- [ ] GitHub repository surface check PASS
- [ ] SBOM generated and reviewed
- [ ] Dependency license inventory reviewed
- [ ] PyMuPDF remains optional and clearly documented
- [ ] Security policy points to private vulnerability reporting
- [ ] No unresolved repository-owner placeholders are active
- [ ] Provider examples contain no real credentials or tenant data
- [ ] Production-readiness claims remain evidence-backed, not configuration-only

Recommended release tag: a reviewed semantic version matching the intended release.

## v1.7 release-candidate assurance

For the v1.7 development line, use an `-rcN` tag until the stable version metadata is deliberately promoted. Example:

```bash
RELEASE_TAG=v1.7.0-rc1
AI_DFIR_RELEASE_TAG="$RELEASE_TAG" python scripts/package_release.py \
  --out-dir "/tmp/AI-DFIR-${RELEASE_TAG}-release"
python scripts/verify_release_candidate_v17.py \
  --release-dir "/tmp/AI-DFIR-${RELEASE_TAG}-release" \
  --version "${RELEASE_TAG#v}"
```

The v1.7 packager stages only files exported from committed `HEAD` plus generated release metadata. Untracked working-tree files are not release inputs. A v1.7 candidate additionally requires:

- `PACKAGE_MANIFEST_V1.7.json` with the source commit and exact packaged-file hashes;
- `RELEASE_VALIDATION_V1.7.json` with exact ZIP/TAR/manifest hashes;
- `RELEASE_CANDIDATE_ASSURANCE_V1.7.json`;
- `RELEASE_NOTES_V1.7.md` (or an exact-version notes file);
- CycloneDX 1.7 SBOM metadata whose AI-DFIR application version matches the candidate version;
- all 56 v1.7 regression tests passing from the extracted release ZIP;
- the deterministic v1.7 release-candidate known-answer self-test passing from the extracted ZIP;
- `SHA256SUMS` covering every release-directory asset except `SHA256SUMS` itself.

A stable v1.7 package must fail closed until stable publication metadata, including `CITATION.cff`, is intentionally updated to the stable release version.
