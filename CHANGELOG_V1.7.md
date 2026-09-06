# AI-DFIR v1.7 — Investigation Integrity & Offline Verification

v1.7 is the stable investigation-integrity and offline-verification layer. It extends the v1.5 signed case-export format rather than replacing it.

## Added

### Unreleased: timestamped historical key-trust records

- offline capture of authenticated policy, complete issuer chain, signed checkpoint, and reproducible ALLOW/DENY;
- domain-separated RFC 3161 requests binding the full record with independent anchor/TSA trust and optional retained digests;
- strict historical root/policy and decision checks across signed TSA accuracy intervals, including interior validity boundaries;
- mandatory current authenticated policy for case use, preserving current revocation, evidence integrity, and other independent gates;
- capture/prepare/verify CLI, case/export/replay integration, explicit historical-result limits, and exclusive output creation;
- 85 focused regressions, synthetic offline acceptance, operator guide, and source/extracted-package assurance;
- no new dependencies, operated TSA, global policy-completeness claim, or proof of actual prior verifier execution.

### Unreleased: online policy and issuer-root delivery

- explicit HTTPS synchronization into an existing independently anchored governed store;
- signed full-chain catch-up across missed rotations, with atomic final-root/policy activation and independent recovery floors;
- publisher bundle preparation that checks the complete chain and final policy before writing;
- certificate/hostname verification, explicit CA support, bounded JSON/framing, and a response deadline;
- no redirects, implicit proxy credentials, remotely supplied trust anchors, or network access during case verification;
- separate transport hashes/TLS receipt and offline authority report, with no global-latest or trusted-time claim;
- 139 focused tests, temporary loopback TLS acceptance, operator guide, and extracted-package assurance;
- no new dependencies, deployed publisher, scheduled synchronization service, or historical authorization proof.

### Unreleased: signed issuer-root governance

- sequential issuer-root rotations approved by both previous and replacement quorums;
- role-separated signatures binding predecessor identity, complete successor configuration, version, and validity;
- independently anchored chain verification with atomic root/policy activation;
- explicit in-place migration preserving existing quorum policy revisions and acceptance times;
- expiry recovery without automatic reset, bounded retained history, and independent root/policy recovery floors;
- offline root preparation, co-signing, activation, inspection, and export/replay enforcement;
- 87 focused tests, synthetic self-test, operator documentation, and extracted-package assurance;
- no new dependencies, live delivery service, historical authorization proof, or TUF-compliance claim.

### Unreleased: checkpoint policy issuer quorum

- configurable thresholds of distinct Ed25519 policy issuer signatures;
- domain-separated approvals binding the policy and independently approved issuer configuration;
- offline co-signing across separate custodians, with explicit partial-signature status;
- strict duplicate, mixed-policy, invalid-signature, and single-issuer downgrade rejection;
- issuer rotation and single-issuer migration without resetting revision state;
- separate signature counts/issuer identities and unassessed human-custodian independence in reports;
- synthetic self-test, 67 focused tests, operator documentation, and extracted-package assurance;
- no new dependencies, deployed governance service, or signed root-update protocol.

### Unreleased: authenticated checkpoint policy updates

- scoped Ed25519 policy envelopes authenticated against independent issuer trust;
- separate issuer/checkpoint keys, strict bounded parsing, and current-clock freshness;
- transactional verifier-owned revision store with lower-revision and equal-revision conflict rejection;
- reauthentication on every use, explicit initialization, and issuer rotation without resetting the revision floor;
- optional independent minimum revision for recovery from older whole-store backups;
- export, verification, and replay enforcement with separate authentication reports;
- offline sign/trust/accept/show CLI, synthetic self-test, and 66 focused tests;
- extracted-package assurance gates; no new dependencies or deployed update service.

### Unreleased: external checkpoint timestamps

- RFC 3161 SHA-256 requests binding the complete signed checkpoint and tenant/case identity;
- local preparation with a fresh 128-bit nonce and optional TSA policy OID;
- offline receipt authentication through OpenSSL 3, with explicit CA trust and a mandatory TSA certificate pin;
- request/response digests, authenticated TSA time/accuracy, and an optional retained-request pin;
- matching enforcement across export, offline verification, and recorded reconstruction;
- bounded ASN.1 and PEM parsing, no implicit system CA trust, and no automatic network submission;
- synthetic TSA acceptance and 68 regression tests, including forged receipts and validly signed negative cases;
- release/source-package gates, analyst workflow, and dependency notices;
- explicit limits for TSA revocation, operator independence, and historical key authorization.

### Unreleased: checkpoint key lifecycle policy

- external verifier-controlled key policy with active, retired, and revoked states;
- UTC validity windows, tenant/case scope, deliberate rotation overlap, and optional canonical policy hash pinning;
- separate cryptographic validity, manifest signer trust, and external policy decisions;
- export and reconstruction refusal when required key policy fails;
- consistent policy options across export, verification, and replay CLIs;
- bounded, strict policy parsing and 57 focused positive/negative tests;
- quick/full release gates and extracted-package assurance for the new profile;
- explicit current-policy semantics without claiming historical signing-time proof.

### Unreleased: investigation provenance and replay

- typed, domain-separated provenance records bound to the signed ledger;
- exported evidence hashes, acyclic lineage, AI/tool references, and analyst target validation;
- references-only context policy with explicit review for retained structured output;
- offline recorded reconstruction and comparison of separately preserved AI executions;
- fixed local RFC 8785 and provider-normalization replay adapters;
- fail-closed handling of missing profiles, modified records, and unsupported replay;
- synthetic acceptance self-test and 30 provenance/replay regression tests;
- quick/full gate and extracted-package assurance integration;
- analyst instructions and corrected architecture/roadmap status.

### Published v1.7.0

- append-only investigation ledger integrity with deterministic checkpoint hashing;
- Ed25519-signed investigation checkpoints;
- explicit separation of signature validity from signer trust;
- v1.5-compatible case exports containing manifest-bound v1.7 verification state;
- offline artifact, ledger, checkpoint, signature, and trust verification;
- hostile ZIP protections and bounded verification resource limits;
- third-party assurance CLI with text and JSON reports;
- explicit verifier exit-code contract for automation;
- detached-working-directory and network-guard assurance testing;
- documented independent-review workflow and trust-boundary interpretation;
- committed-HEAD-only release staging that excludes untracked working-tree residue;
- version-aware v1.7 package manifests and release-validation reports;
- packaged-artifact SHA-256 coverage and source-commit binding;
- CycloneDX application-version binding for release candidates;
- deterministic release-candidate known-answer verification;
- extracted-package enforcement of all 56 v1.7 regression tests;
- dedicated v1.7 release-candidate assurance verification;
- published-release verification that permits only the known post-packaging SLSA provenance sidecar while rejecting arbitrary extra assets;
- clean re-download and verification of the final GitHub release surface after publication.

## Compatibility

The outer case-export manifest remains `ai-dfir/case-export-manifest/v1.5`. A v1.7 verifier requires the additional manifest-bound v1.7 ledger/checkpoint/trust members. A v1.5-only package remains a valid v1.5 export but is reported as unsupported for v1.7 offline verification.

## Trust boundary

The exported package does not establish its own outer trust anchor. A reviewer must obtain the export public key independently. Package-contained checkpoint public keys are public verification material whose trust is meaningful because the v1.7 trust store is covered by the externally verified v1.5 manifest.

## Release status

v1.7.0 is the stable release of the investigation-integrity and offline-verification line. Stable promotion follows successful v1.7.0-rc2 validation of committed-source packaging, offline verification, release assurance, SLSA provenance separation, and independent verification of the final published GitHub release surface.
