# Project Governance

AI-DFIR uses maintainer-led governance with evidence-integrity changes receiving
higher review scrutiny than ordinary documentation or UI changes.

## Roles

- **Maintainers** approve releases, security fixes, and architectural changes.
- **Evidence reviewers** review hashing, signing, acquisition, chain of custody,
  legal hold, retention, and report semantics.
- **Detection reviewers** validate attack-surface and Evidence Pack changes.
- **Contributors** propose code, tests, documentation, and provider adapters.

## Required review

The following should receive independent review before release:

- cryptographic formats and trust decisions;
- tenant isolation and authorization;
- provider-native collectors;
- containment and recovery;
- Evidence Pack conclusion gates;
- production-readiness claims;
- release artifacts and manifests.

## Release rule

A release is not complete until its final archive has been extracted into a clean
location and the release acceptance suite has run against the extracted copy.
