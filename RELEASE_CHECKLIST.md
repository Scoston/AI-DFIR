# Release Checklist

A release candidate must satisfy all items before the tag is published.

## Code and tests

- [ ] all top-level Python files compile;
- [ ] Analyst Workbench JavaScript passes `node --check`;
- [ ] `v15_selftest.py` passes;
- [ ] v1.4/v1.3/v1.2 compatibility suites pass;
- [ ] all cataloged Evidence Pack synthetic fixture assessments pass;
- [ ] high-fidelity synthetic scenario smoke tests pass;
- [ ] no test writes outside its temporary workspace;
- [ ] no production network access is required for default tests.

## Security and licensing

- [ ] `scripts/secret_scan.py` passes;
- [ ] dependency/license inventory reviewed;
- [ ] optional AGPL PDF dependency is not in default installation;
- [ ] no private key or token fixture contains a real secret;
- [ ] GitHub workflow permissions are minimal;
- [ ] `SECURITY.md` is present.

## Artifact

- [ ] package manifest generated;
- [ ] `SHA256SUMS` generated;
- [ ] source ZIP and TAR.GZ generated;
- [ ] final ZIP extracted to a new directory;
- [ ] full release check rerun from extracted ZIP;
- [ ] release validation document records exact artifact SHA-256.

## Human review

- [ ] analyst/HITL documents reviewed;
- [ ] deployment docs reviewed;
- [ ] changelog/release notes reviewed;
- [ ] production-readiness language does not overclaim deployment certification.
