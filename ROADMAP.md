# Roadmap

## Current stable release: v1.7.0

v1.7.0 remains the stable investigation-integrity and offline-verification release.
It extends the earlier signed case-export architecture with investigation-ledger
integrity, signed checkpoints, explicit signer-trust semantics, committed-source
release assurance, and offline case verification. The current catalog contains
111 Evidence Packs.

A released GitHub artifact passing repository gates does **not** certify a specific
enterprise deployment as production-ready. Deployment-specific trust, identity,
retention, database, HSM/KMS, collector, provider, evidence-storage and external
assessment controls remain operator responsibilities.

## v1.8 development line — Agentic Forensics & Runtime Reconstruction

v1.8 is now the active development direction. Its organizing primitive is the
**Agent Execution Record (AER)**: an evidence-bound graph that reconstructs observable
execution from trigger/human request through agent context, retrieval/memory,
identity/authority, policy/approval, protocol/tool activity and side effects.

The first v1.8 milestone implements six connected capability families:

- Agent Execution Record with machine-readable schema and explicit unknowns;
- MCP `2026-07-28` recorder plus inert/offline replayer;
- RAG and memory provenance with chunk and state-transition custody;
- OpenTelemetry GenAI non-destructive adapter with raw-span preservation;
- OWASP Agentic ASI01–ASI10 / MITRE ATLAS evidence-gated mappings;
- AI/ML-BOM inventory with dependency graph and conservative CycloneDX 1.7 projection.

The profile never claims capture of private model chain-of-thought. Hash binding does
not establish source authenticity, framework mappings are not attack verdicts, and
standards-shaped output is not treated as conformance without actual validation.

See:

- [v1.8 architecture and evidence boundaries](docs/reference/AGENTIC_RUNTIME_RECONSTRUCTION_V1.8.md)
- [v1.8 development roadmap](docs/reference/ROADMAP_V1.8.md)

## v1.7 development capabilities retained

The repository also contains additional implemented v1.7 capabilities that are not
part of the published v1.7.0 release assets. Each remains bounded by the claims and
acceptance evidence documented in its reference guide.

### Representation integrity and visible rendering

- isolated PDF raster/OCR with pinned local Docker image, no network or host mounts,
  bounded grayscale pages, English OCR, source/image/text custody, fail-closed cleanup,
  and 12-case native qualification;
- bounded grayscale PNG OCR bridge with deterministic PNG-to-PDF identity binding;
- bounded two-source representation comparison;
- constrained HTML/CSS, DOCX, text, PDF and font/static-content workers.

The tested renderer profiles do not establish arbitrary-format compatibility,
source authenticity, complete visible rendering, general OCR accuracy or production
qualification.

### Investigation replay and evidence integrity

Implemented development profiles include:

- investigation provenance/reference validation and recorded reconstruction;
- Evidence Pack conclusion-gate replay for all 111 catalog packs;
- pinned raw-evidence reassessment and nested schema comparison;
- native CloudTrail, Google Cloud Audit, Azure Activity Log and Log Analytics replay;
- Google Cloud Logging and Log Analytics acquisition-context capture;
- lossless Log Analytics numeric replay and resource/GET/form variants;
- optional CASE/UCO 1.5.0 inventory/lineage exchange;
- private transparency snapshots, inclusion/consistency proofs and witnessing.

### Trust, checkpoint and policy governance

Implemented development profiles include:

- verifier-controlled checkpoint key lifecycle and scoped trust;
- RFC 3161 checkpoint timestamp request/verification;
- authenticated policy packages and revision rollback protection;
- issuer quorum and signed issuer-root rotation;
- authenticated HTTPS policy delivery with optional mTLS client identity;
- controlled policy synchronization scheduling;
- timestamped historical key-trust records.

These profiles have synthetic/offline acceptance where documented. They do not claim
that an external TSA, publisher, HSM, independent custodian or production scheduler
has been deployed.

### Parser and corpus assurance

Implemented development assurance includes deterministic hostile-input corpora,
bounded archive intake/campaigns, coverage-guided parser/archive fuzzing,
structure-preserving DOCX/ZIP mutation targets and a pinned persistent corpus.
Finite or coverage-guided synthetic campaigns do not establish exhaustive parser
security or native sanitizer qualification.

## Qualification matrices

- v1.7 remaining qualification requirements:
  [docs/reference/ROADMAP_QUALIFICATION_V1.7.md](docs/reference/ROADMAP_QUALIFICATION_V1.7.md)
- v1.8 implementation and qualification sequence:
  [docs/reference/ROADMAP_V1.8.md](docs/reference/ROADMAP_V1.8.md)

A capability is treated as qualified only when its code, analyst interpretation and
actual acceptance evidence exist for the environment being claimed.

## Repository-controlled work still available

The following can continue with synthetic fixtures and CI while preserving explicit
limits and conservative claims:

- v1.8 provider/framework-native agent capture adapters;
- multi-span OpenTelemetry-to-AER graph assembly;
- agentic Evidence Packs for ASI01–ASI10;
- CycloneDX 1.7 validation and expected-vs-observed AI/ML-BOM comparison;
- versioned A2A/inter-agent capture;
- browser/computer-use side-effect evidence;
- differential execution comparison;
- temporal reconstruction and clock uncertainty;
- privacy-preserving/redacted evidence views bound to retained originals;
- hostile MCP/RAG/memory/OTel corpora and fuzz targets;
- additional v1.7 visible-input formats, OCR/layout corpora, provider parsers,
  grammar-aware mutations and CASE/UCO modeling.

## Work requiring external inputs or infrastructure

The following cannot be truthfully completed by repository code alone:

- authoritative historical policy/revocation and custody evidence;
- operated policy-delivery service topology and durable/HA scheduler coordination;
- an independently operated TSA, archival revocation evidence and renewal policy;
- authorized live provider, model, MCP, vector-store, memory or OTel targets and credentials;
- representative PostgreSQL/HA staging workloads, topology, SLOs and failover data;
- a selected HSM/KMS/PKCS#11 or accessible hardware-backed signing target;
- independently operated transparency/witness custodians and fork monitoring;
- authoritative provider source inventories, retention evidence and compatibility populations;
- named external CASE/UCO/case-management and agent-protocol interoperability targets;
- independent penetration testing/certification scope, assessor and report.

No live cloud credentials, customer evidence, private keys or production secrets should
be committed to satisfy these items.

## Release discipline

Development work is not promoted merely because source tests pass. Release and
qualification claims remain tied to committed source, deterministic gates, retained
acceptance evidence and the exact environment exercised. Externally gated items remain
open until their required environment or authoritative inputs exist.
