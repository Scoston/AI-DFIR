# Roadmap

## Current release: v1.7.0

v1.7.0 is the stable investigation-integrity and offline-verification release.
It extends the earlier signed case-export architecture with investigation-ledger
integrity, signed checkpoints, explicit signer-trust semantics, committed-source
release assurance, and offline case verification. The current catalog contains
111 Evidence Packs.

A released GitHub artifact passing the repository gates does **not** certify a
specific enterprise deployment as production-ready. Deployment-specific trust,
identity, retention, database, HSM/KMS, collector, provider, and evidence-storage
controls remain operator responsibilities.

## Development status

The repository contains additional implemented capabilities that are not part of
the published v1.7.0 release assets. Each capability remains bounded by the claims
and acceptance evidence documented in its reference guide.

### Representation integrity and visible rendering

- [Isolated PDF raster and OCR](docs/reference/ISOLATED_PDF_RENDERING_V1.7.md):
  pinned local Docker image, no network or host mounts, bounded grayscale pages,
  English OCR, source/image/text custody, fail-closed cleanup, and actual native
  qualification. The current native workflow exercises **12 synthetic PDF cases**:
  ten available cases plus malformed and over-page-limit rejection cases.
- [Bounded grayscale PNG OCR bridge](docs/reference/PNG_OCR_BRIDGE_V1.7.md):
  strict 8-bit grayscale PNG validation, deterministic PNG-to-PDF image bridge,
  original/derived hash custody, reuse of the same isolated renderer, and actual
  native PNG qualification. RGB and malformed PNGs remain deliberately unsupported.
- [Bounded two-source representation comparison](docs/reference/BOUNDED_REPRESENTATION_COMPARISON_V1.7.md):
  fixed worker limits, exact source bindings, explicit unavailable states, and
  critical source-versus-visible divergence reporting.
- [Bounded content workers](docs/reference/CONTENT_WORKERS_V1.7.md),
  [contained HTML/CSS intake](docs/reference/HTML_INTAKE_V1.7.md), and
  [bounded DOCX intake](docs/reference/DOCX_INTAKE_V1.7.md) provide constrained
  document/static-content analysis without claiming complete native rendering.

The current renderer workflow qualifies the tested PDF and grayscale-PNG profiles
on its tested Ubuntu/Docker/image combination only. Source authenticity, complete
visible rendering, OCR accuracy, arbitrary-format compatibility, and production
qualification remain false or unknown unless independently established.

### Investigation replay and evidence integrity

Implemented development profiles include:

- investigation provenance/reference validation and recorded reconstruction;
- Evidence Pack conclusion-gate replay for all 111 catalog packs;
- pinned raw-evidence reassessment and nested schema comparison;
- native CloudTrail, Google Cloud Audit, Azure Activity Log, and Log Analytics
  replay profiles;
- Google Cloud Logging and Log Analytics acquisition-context capture profiles;
- lossless Log Analytics numeric replay and resource/GET/form variants;
- optional CASE/UCO 1.5.0 inventory/lineage exchange;
- private transparency snapshots, inclusion/consistency proofs, and witnessing.

See the individual guides under [`docs/reference/`](docs/reference/) and
[Investigation replay](docs/reference/INVESTIGATION_REPLAY_V1.7.md).

### Trust, checkpoint, and policy governance

Implemented development profiles include:

- verifier-controlled checkpoint key lifecycle and scoped trust;
- RFC 3161 checkpoint timestamp request/verification;
- authenticated policy packages and revision rollback protection;
- issuer quorum and signed issuer-root rotation;
- authenticated HTTPS policy delivery with optional mTLS client identity;
- controlled policy synchronization scheduling;
- timestamped historical key-trust records.

These profiles have synthetic/offline acceptance where documented. They do not
claim that an external TSA, publisher, HSM, independent custodian, or production
scheduler has been deployed.

### Parser and corpus assurance

Implemented development assurance includes:

- deterministic hostile-input parser corpora;
- bounded archive metadata intake and hostile archive campaigns;
- coverage-guided parser/archive fuzzing with retained diagnostics;
- structure-preserving DOCX/ZIP mutation targets and a pinned persistent corpus.

Finite and coverage-guided synthetic campaigns do not establish exhaustive parser
security or native sanitizer qualification.

## Qualification matrix

The authoritative list of what remains to be qualified is maintained in
[Remaining roadmap qualification requirements](docs/reference/ROADMAP_QUALIFICATION_V1.7.md).
A capability should be marked complete only when its code, analyst interpretation,
and actual acceptance evidence exist for the claimed environment.

## Remaining work that can be advanced in-repository

These items can be developed further with synthetic fixtures and repository CI,
but each expansion must preserve explicit limits and conservative evidence claims:

- additional visible-input formats such as JPEG or explicitly bounded color/alpha
  image profiles;
- additional OCR languages, fonts, layouts, and larger representation-hostile
  rendering corpora;
- additional deterministic provider/export parsers once a precise input contract
  and forensic proposition are selected;
- broader grammar-aware mutation profiles and reproducible native-sanitizer jobs;
- deeper CASE/UCO investigation modeling and import logic once a named external
  interoperability target/version is selected.

## Remaining work that requires external inputs or infrastructure

The following cannot be truthfully completed by repository code alone:

- authoritative historical policy/revocation and custody evidence;
- operated policy-delivery service topology and durable/HA scheduler coordination;
- an independently operated TSA, archival revocation evidence, and renewal policy;
- authorized live provider acquisition/comparison targets and credentials;
- representative PostgreSQL/HA staging workloads, topology, SLOs, and failover data;
- a selected HSM/KMS/PKCS#11 interface or accessible hardware-backed signing target;
- independently operated transparency/witness custodians and fork monitoring;
- authoritative provider source inventories, scope/retention evidence, and versioned
  compatibility populations;
- named external CASE/UCO/case-management interoperability targets;
- an independent penetration-test/certification target, assessor, scope, and report.

No live cloud credentials, customer evidence, private keys, or production secrets
should be committed to satisfy these items.

## Release discipline

Development work is not promoted merely because source tests pass. Release and
qualification claims must remain tied to committed source, deterministic gates,
retained acceptance evidence, and the exact environment they actually exercised.

Roadmap items are not treated as implemented evidence capabilities until code,
documentation, and acceptance tests are present; externally gated items remain
open until their required environment or authoritative inputs exist.
