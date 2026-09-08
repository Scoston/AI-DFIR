# AI-DFIR v1.7 — Investigation Integrity & Offline Verification

v1.7 is the stable investigation-integrity and offline-verification layer. It extends the v1.5 signed case-export format rather than replacing it.

## Added

### Unreleased: bounded DOCX intake and embedded-font analysis

- immutable ZIP snapshot, selected-part expansion and XML tree budgets, DTD/entity rejection, and strict package-name/relationship handling;
- selected part CRC/size/hash receipts with explicit uninspected payloads and unknown authenticity/completeness;
- fixed Linux font child with CPU, memory, output, and elapsed limits; incomplete analysis requires review while existing critical findings remain;
- 133 DOCX regressions, synthetic acceptance/rejection, source/extracted/independent package gates, and a new pure-loader fuzz target;
- coverage harness now has 18 profiles, 36 pinned preflight cases, and 125 regressions; defusedxml is a PSF-licensed runtime dependency;
- no independent rendering, full OOXML conformance, or native parser qualification claim.

### Unreleased: coverage-guided parser and archive fuzzing

- optional pinned Atheris 3.1.0 bytecode instrumentation for twelve provider/context and five archive profiles, using only committed synthetic seeds;
- repeated normalization/replay/claim oracles, preserved selector-prefixed failures, private exclusive output, and explicit execution, input, log, CPU, RSS, and timeout bounds;
- required 5,000-input PR/main CI runs and 20,000-input scheduled/manual runs with rotating seeds; reports and failure diagnostics retained for 14 days;
- 115 engine-independent regressions and pinned 34-case preflight in source/extracted gates, with separate optional-engine reports and no native-sanitizer, sandbox, exhaustive-coverage, or evidence-authenticity claim.

### Unreleased: bounded archive intake and hostile corpus

- bounded immutable ZIP32/TAR/gzip/bzip2/xz metadata profiles, early central-directory/header counts, capped container expansion, and explicit unsupported ZIP64/sparse/ambiguous-header rejection;
- consistent local/central ZIP metadata, nonoverlapping member ranges, complete TAR blocks/termination, bounded PAX/GNU extensions, and conservative portable path/link/control-surface findings;
- existing archive CLI and content-intake gate now use the bounded parser; added compressed-TAR suffix coverage, redacted parse failures, complete bounded member lists, and private exclusive CLI output;
- 190 regressions and a pinned 680-case synthetic campaign across five profiles, with repeated outcomes and blocked extraction/member-content/network/process APIs; no payload-integrity, extraction-safety, or coverage-guided fuzzing claim.

### Unreleased: CASE/UCO inventory exchange

- optional bounded JSON-LD inventory/lineage view using CASE/UCO 1.5.0, with local fixed contexts and archive-scoped deterministic instance IDs;
- immutable ZIP snapshot verification, explicit tenant/case identity, existing external policy/timestamp/history gates, and retained artifact hashes, sizes, package paths, labels, record commitments, and secondary inputs;
- full graph comparison with integer-type preservation, exclusive private CLI output, redacted failures, and explicit unsigned/partial/recorded-only semantics;
- 101 regressions plus pinned official CASE validation, invalid-graph rejection, and RDF round-trip acceptance in CI and full source/extracted gates; RDF dependencies are optional development/release tools.

### Unreleased: pinned nested schema comparison

- a twelfth fixed adapter compares complete retained object/array/JSONL populations against an independently pinned baseline;
- collision-resistant typed member/array path identities, every-node kind and occurrence counts, record presence, and added/removed/changed observed shapes;
- separate byte/count/shape differences, no provider-change or compatibility inference, and no evidence-quality or conclusion promotion;
- signed baseline artifact references, independent pin/case checks, second-input cycle detection, opt-in full replay, and exclusive CLI output;
- 182 focused regressions including empty signed JSONL evidence, analyst guide, and source/extracted/independent package gates;
- no new dependency, live acquisition, inferred record selection, embedded-string parsing, or changes to existing raw-evidence validation semantics.

### Unreleased: deterministic hostile-input parser corpus

- twelve fixed provider response/context profiles with 3,318 default synthetic cases and pinned corpus/outcome digests;
- repeatable structural deletion/replacement, encoding, truncation, depth, duplicate-key, numeric, Unicode, and embedded-JSON mutations without rounding untouched numeric tokens;
- repeated normalization, exact source/context binding, bounded output, authority/coverage claim checks, and matching/altered replay oracles;
- Python network/process guards, bounded redacted failure reports, exclusive CLI output, 76 fault-injection/acceptance regressions, and source/extracted-package gates;
- no production parser change, new dependency, arbitrary corpus/module loading, live acquisition, gate promotion, or exhaustive-security claim.

### Unreleased: witnessed private transparency-log proofs

- bounded immutable snapshots, Ed25519-signed log heads and role-bound witness signatures under an independent canonical trust pin;
- SHA-256 history-tree inclusion and prefix proofs; witnesses verify state against an independently retained prior head before signing;
- offline init/append/cosign/proof/verify commands, protected PKCS8 inputs, exclusive private outputs, explicit partial quorums, and redacted failures;
- 160 focused regressions, synthetic witnessed acceptance, analyst guide, and source/extracted-package assurance;
- security correction: legacy unsigned receipt flags no longer pass cryptographic inclusion validation; recorded assertion comparison remains separate;
- no new dependencies, network log deployment, replay adapter, automatic gate promotion, or claim of independent operators, trusted time, or global fork freedom.

### Unreleased: pinned raw-evidence reassessment

- an eleventh fixed adapter recomputes byte/digest, strict parse, literal-text, and every-record field checks under an explicit canonical rules pin;
- five bounded formats, exact numeric-kind observation, field presence/type counts, and automatic top-level schema fingerprints;
- separate signed rules input, case/pin/reference/cycle checks, complete offline assessment comparison, and no quality or authority promotion;
- 190 focused regressions, synthetic signed acceptance including failed validation and empty evidence, analyst guide, and source/extracted-package assurance;
- no new dependencies, live acquisition, or changes to historical recorded quality ratings and gate replay.

### Unreleased: Google Cloud Logging capture and context replay

- a tenth fixed adapter binds one entries.list request to exact Audit Log response bytes, ordered resource assertions, opaque filter/order/page observations, and signed offline replay;
- explicit collector capture mode uses a fixed verified-TLS endpoint, bounded undecoded reads, private exclusive artifacts, and failed-observation handling;
- continuation on an empty page remains incomplete; effective scope, provider origin, prior-page relationships, and full coverage remain unverified;
- 228 focused regressions, synthetic signed acceptance, analyst guide, and source/extracted-package assurance;
- no new dependencies or live provider acceptance; existing native Audit Log and Azure capture profiles remain compatible.

### Unreleased: lossless Log Analytics numeric replay

- a ninth fixed adapter preserves wide integer/decimal/real text and distinguishes JSON numeric tokens from numeric strings;
- full signed 64-bit integers, exact bounded decimal checks, negative-zero/exponent/trailing-zero preservation, and collision-free tagged hashes for opaque values;
- bounded typed tables, opaque resource permissions, unchanged partial/unknown semantics, and signed offline replay;
- 171 focused regressions, synthetic acceptance, two original-projection golden hashes, analyst guide and source/extracted-package assurance;
- no new dependencies or live acquisition; original table/context/capture profiles and historical release verification remain unchanged.

### Unreleased: form-encoded Log Analytics GET and workspace lists

- explicit workspace/resource form GET profiles with strict plus-before-percent decoding, exact URL/order binding, and bounded additional workspace GUID lists;
- automatic capture with explicit GET encoding selection, decoded credential checks, and no fallback after failed acquisition;
- 123 focused regressions, synthetic signed replay, original percent-only profile compatibility, analyst guide, and full source/extracted-package assurance;
- no new dependencies or live provider acceptance; historical release verification remains supported.

### Unreleased: resource-scoped Log Analytics capture and replay

- explicit resource POST/GET profiles, bounded public resource paths, exact resource/query/response binding, and signed multi-input replay;
- automatic capture with explicit scope selection and existing protected transport/output semantics;
- separate resource table profile with opaque permission observations, unknown completeness after error-free HTTP success, and no inferred RBAC decision;
- 142 focused regressions, synthetic signed acceptance, unchanged workspace POST/GET capture artifact hashes, and source/extracted-package assurance;
- no new dependencies, live acquisition, or deployment; historical release verification remains supported.

### Unreleased: automatic Log Analytics workspace GET capture

- explicit `--capture-method GET` and keyword-only API method selection produce the response/context/projection artifacts for the reviewed GET replay profile;
- bounded single-pass URL construction, actual prepared/observed GET comparison, absent-body retention, and configured-credential checks against decoded parameters;
- shared verified-TLS, no-redirect/retry/preload/decode transport and exclusive receipt publication, with explicit failed/partial/unknown result handling and no POST fallback;
- 143 focused regressions, synthetic acquisition and signed offline replay, unchanged default/explicit POST artifact digests, analyst guide, and full source/extracted-package assurance;
- no new dependencies or live acceptance credentials; conditional package verification preserves historical releases.

### Unreleased: Log Analytics workspace GET context replay

- explicit `workspace-get` input profile in the existing context adapter and CLI, with recorded absent body and query/optional timespan in a fixed public workspace URL;
- strict one-pass UTF-8 percent decoding, bounded URLs and decoded values, duplicate/unknown parameter rejection, and separate exact URL/decoded parameter digests;
- signed multi-input replay detects query, URL spelling/order, header, and context substitution while retaining incomplete/unknown results and unverified scope/execution/origin;
- 160 focused regressions, synthetic signed offline acceptance, unchanged reviewed POST projection digests, analyst guide, and full source/extracted-package assurance;
- no new dependencies, live GET acquisition, or changed POST capture behavior; conditional verification preserves historical release compatibility.

### Unreleased: automatic Log Analytics acquisition-context capture

- explicit `azure_foundry_logs --capture-context` mode with bounded parameter-file input and unchanged response-only behavior;
- prepared request observations, exact response entity-body preservation, distinct selected response header names, and automatic replay-compatible context/projection artifacts;
- one fixed HTTPS POST with TLS verification, no redirects/retries/environment credential or proxy merge, bounded undecoded reads, and explicit partial/unsupported/failure states;
- private exclusive output creation and final receipt publication, with no complete claim after partial writes;
- 114 focused regressions, synthetic acquisition and signed offline replay acceptance, analyst documentation, and source/extracted-package assurance;
- no new dependencies, live acceptance credentials, or automatic acquisition during replay; historical release verification remains supported.

### Unreleased: Log Analytics retained request-context binding

- explicit workspace POST context profile with exact response digest/size binding, selected header observations, and opaque query/scope digests;
- separately bound context artifact as a second derivation input, with reference and cycle validation before signed-case replay;
- offline normalize/compare CLI, preserved partial-result semantics, and no inferred effective scope, actual execution, origin, or completeness;
- 171 focused regressions, synthetic offline acceptance, analyst guide, and source/extracted-package assurance;
- no new dependencies or live acquisition changes; historical release verification remains supported.

### Unreleased: Log Analytics query-result import and offline replay

- explicit native tables/columns/rows profile with strict typed cells, row-width validation, global budgets, and ordered schema/value bindings;
- preserved fractional timestamps, numeric/Boolean observations, opaque string/dynamic/GUID cell hashes, and duplicate/conflicting rows;
- explicit PartialError preservation, separately reported replay success and incomplete collection, and no query execution or inferred source/scope/event counts;
- corrected Azure collector completeness metadata and preserved its raw response and existing Boolean receipt contract;
- normalize/compare CLI, fixed signed-case integration, 224 focused regressions, analyst guide, and source/extracted-package assurance;
- no new dependencies or acquisition endpoints; conditional package requirements retain historical release-verification compatibility.

### Unreleased: Azure Activity Log import and offline replay

- explicit native REST value/nextLink and EventData array profiles with strict bounded parsing and no skipped events;
- exact source/canonical event digests, retained order and duplicate IDs, and seven-to-nine-digit fractional timestamp preservation;
- separate caller/claim aliases, authorization observations, invariant/translated labels, and event/operation/correlation identifiers;
- opaque payload/URI/continuation digests and explicit limits on management-plane coverage, effects, attribution, and collection completeness;
- normalize/compare CLI with exclusive output creation, fixed signed-case replay, 207 focused regressions, analyst guide, and source/extracted-package assurance;
- no new dependencies or live acquisition changes in this Activity Log profile; Log Analytics tabular responses use the separate profile above, and historical release verification stays compatible.

### Unreleased: Google Cloud Audit Logs import and offline replay

- explicit native entries.list response and JSON-array profiles with bounded strict parsing and no skipped entries;
- exact source/canonical entry digests, original nanosecond timestamps, recorded delegation order, and separate per-resource permission checks;
- retained principal email/subject, status presence/code, operation markers, hashed payloads/claims, and explicit collection/authenticity limits;
- normalize/compare CLI, exclusive output creation, and fixed signed-case replay integration;
- 163 focused regressions, synthetic offline acceptance, analyst guide, and source/extracted-package assurance;
- no new dependencies, live acquisition changes, attribution inference, or historical release-verification incompatibility.

### Unreleased: native CloudTrail import and offline replay

- explicit native Records and LookupEvents JSON profiles with strict bounded parsing, no fallback, and no skipped events;
- exact source/canonical event digests, preserved order and duplicate IDs, distinct caller/session-issuer identities, and hashed payloads;
- wrapper consistency checks, pagination reporting, and no automatic success, human attribution, collection completeness, or AWS-origin claim;
- standalone normalize/compare CLI, exclusive output creation, and fixed signed-case replay integration;
- 130 focused regressions, synthetic offline acceptance, analyst guide, and source/extracted-package assurance;
- no new dependencies or live acquisition; existing flat-row normalizers and historical release verification remain compatible.

### Unreleased: recorded Evidence Pack conclusion-gate replay

- a fixed offline adapter reproduces the existing gate calculation from exact retained pack rules and complete recorded quality states;
- explicit canonical pack/case binding, bounded schemas, alias/quality-threshold handling, and separate replay-versus-conclusion status;
- prepare/verify CLI, immutable retained assessments, exclusive snapshot creation, and signed-case reconstruction integration;
- shared pure gate calculation preserves existing assessment behavior without rescanning files or executing pack-supplied code;
- 96 focused tests, all-111-pack catalog coverage, synthetic signed-case acceptance, and source/extracted-package assurance;
- the Kubernetes exposure pack now uses `network_context` for its conditional network artifact, removing a duplicate ID while keeping the mandatory `network` gate binding;
- no new dependencies or raw-evidence quality revalidation; historical ambiguous snapshots are rejected rather than silently rewritten.

### Unreleased: controlled policy synchronization scheduling

- strict operator-owned job definitions with separate store paths, approved anchor pins, HTTPS endpoints, and optional mTLS inputs;
- offline preflight, explicit single-pass/watch commands, per-job JSON results, and graceful SIGINT/SIGTERM handling;
- monotonic completion-based deadlines, bounded exponential backoff/jitter, sequential execution, and overlapping-round rejection;
- approved configuration snapshots and per-attempt anchor/credential checks; accepted store state survives scheduler restarts;
- existing quorum, root-chain, rollback/floor, atomic activation, and offline verification controls preserved;
- 85 focused regressions, synthetic scheduled mTLS acceptance, operator guide, and source/extracted-package assurance;
- no new dependency; persistent timing state, multi-process coordination, publisher deployment, and service supervision remain outside this profile.

### Unreleased: policy delivery client certificate authentication

- explicit TLS client certificate/key/password-file options and independent client leaf pinning;
- current client-only X.509 purpose, strong key/digest profile, bounded PEM input, and matching PKCS8 validation;
- protected secret-file checks, exact private snapshots for OpenSSL loading, cleanup, and no interactive password prompts;
- credential metadata separated from issuer authority and unproven publisher-side client authorization;
- TLS session secret logging disabled; server trust, redirect rejection, policy signatures, rollback, and offline verification preserved;
- 80 focused regressions, including malformed-PEM runtime bounds, synthetic mutual-TLS acceptance, operator guide, and source/extracted-package assurance;
- no new dependency, deployed publisher, or credential issuance/revocation service; scheduling is provided by the separate profile above.

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
- no new dependencies, deployed publisher, or historical authorization proof; scheduling is provided by the separate profile above.

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
