# Roadmap

## Current release: v1.7.0

v1.7.0 adds signed investigation checkpoints, offline case verification, and
committed-source release assurance to the earlier production-assurance controls.
The current catalog contains 111 Evidence Packs.

## Implemented in development, unreleased

Bounded text/PDF workers, standalone-font intake, and exclusive report output are
implemented in development. Fixed Linux processes cap CPU, address space, elapsed
time, and response bytes; exact source bindings and strict result checks preserve
unknowns. The gate and specialist text/document/font CLIs use these boundaries,
with 100 regressions and optional synthetic PyMuPDF acceptance. Broader native
sanitizer/format qualification, persistent fuzz corpus curation, and independent
rendering remain open. See [Bounded content workers](docs/reference/CONTENT_WORKERS_V1.7.md).

Contained HTML/CSS intake is implemented in development: directory-handle local
reads, no resource symlinks, safe stylesheet-relative references, strict bounded
source/parser/resource profiles, selected-byte receipts, and explicit unresolved
resources. The content gate reuses one HTML snapshot and bounds other text reads.
There are 88 regressions and two pure static fuzz profiles. General text/PDF
processing and standalone-font/gate output now have a separate bounded worker
profile. Independent rendering remains open. See
[Contained HTML/CSS intake](docs/reference/HTML_INTAKE_V1.7.md).

Bounded selected-part DOCX intake is implemented in development: immutable source
binding, ZIP/XML/font budgets, forbidden DTD/entities, literal internal font
relationships, selected CRC/size verification, explicit uninspected scope, and
resource-limited embedded-font geometry. There are 133 regressions and a pure
DOCX loader fuzz target. HTML/CSS containment and general text/font/PDF process
boundaries are now implemented; broader native parser qualification and
independent rendering remain open. See
[Bounded DOCX intake](docs/reference/DOCX_INTAKE_V1.7.md).

Coverage-guided parser fuzzing is implemented in development: 20 fixed synthetic
provider/context/archive/DOCX/HTML/CSS profiles, Atheris bytecode instrumentation, repeated
replay and claim oracles, bounded child execution, retained failure diagnostics,
required PR/main campaigns, and a larger scheduled/manual campaign. Source and
extracted gates separately validate the engine-independent harness and pinned
preflight. Persistent corpus curation, native sanitizer qualification, broader
documents, and independent rendering remain open. See
[Coverage-guided fuzzing](docs/reference/COVERAGE_FUZZING_V1.7.md).

Bounded archive metadata intake is implemented in development: ZIP32, TAR,
gzip/bzip2/xz-wrapped TAR, explicit expansion/member/header/name/output limits,
header-consistency checks, portable path/link findings, and integration with the
existing archive CLI/intake gate. A pinned 680-case hostile campaign and 190
regressions cover five profiles without extraction. The separate coverage-guided
job now includes these profiles; broader documents and rendering remain open. See
[Bounded archive intake](docs/reference/ARCHIVE_INTAKE_V1.7.md).

An optional CASE/UCO 1.5.0 inventory exchange is implemented in development:
bounded immutable signed-case verification, explicit identity and external trust
gates, deterministic JSON-LD artifact/lineage views, secondary input references,
full offline graph comparison, and official CASE validation with RDF round-trip
acceptance. Omitted records and unmapped files are counted. Full investigation
modeling, bidirectional import, and interoperability with a particular external
case-management deployment remain open. See [CASE/UCO exchange](docs/reference/CASE_EXCHANGE_V1.7.md).

Nested schema observation/comparison is implemented in development: complete
bounded object/array/JSONL populations, typed member/array paths, kind/occurrence
and record-presence counts, explicit baseline-byte pins, added/removed/changed
shape observations, and signed offline replay with second-input lineage checks.
Observed differences do not prove a provider schema change or measure uncollected
sources. See [Nested schema comparison](docs/reference/NESTED_SCHEMA_DRIFT_V1.7.md).

A deterministic hostile-input parser corpus is implemented in development:
twelve fixed native response/context profiles, 3,318 default cases with pinned
input/outcome digests, structural/encoding/embedded-JSON mutations, repeated
normalization, replay and claim checks, bounded failure reports, and fault-injected
harness acceptance. This finite synthetic campaign is required in source and
extracted releases; the separate coverage-guided job now includes all twelve
profiles. Broader document corpora remain open. See [Hostile parser corpus](docs/reference/PARSER_HOSTILE_CORPUS_V1.7.md).

Private transparency-log snapshots and multi-key witnessing have an implemented
offline profile: immutable bounded states, signed heads, independently pinned
log/witness trust, inclusion proofs, and optional prefix consistency against an
independently retained prior head. Witness commands check the complete state and
prior history before signing. Existing Evidence Pack artifacts remain separately
reviewed; there is no automatic gate promotion. Operated services, independent
witness custody, global fork monitoring, and archival key governance remain open.
See [Private transparency](docs/reference/PRIVATE_TRANSPARENCY_V1.7.md).

Investigation provenance/reference validation, evidence lineage validation,
recorded AI/tool/analyst reconstruction, preserved-execution comparison, and
twelve fixed deterministic replay adapters: RFC 8785, legacy provider normalization,
recorded Evidence Pack gates, native CloudTrail projection, Google Cloud Audit
projection, native Azure Activity Log projection, Log Analytics table projection,
lossless Log Analytics numeric projection, retained Log Analytics request-context
binding, Google Cloud Logging request-context binding, pinned raw-evidence
reassessment, and pinned nested schema comparison. See
[Investigation replay](docs/reference/INVESTIGATION_REPLAY_V1.7.md) for the
implemented profile and acceptance requirements.

Evidence Pack conclusion-gate replay is implemented in development: retained pack
rules, complete recorded quality states, canonical pack binding, strict bounded
inputs, and offline comparison within signed case reconstruction. Its pure gate
calculation is shared with the assessment engine. All 111 current catalog packs
fit the profile; raw evidence quality is not reassessed or implicitly approved.
See [Evidence Pack gate replay](docs/reference/EVIDENCE_PACK_REPLAY_V1.7.md).

Pinned raw-evidence reassessment is implemented in development: explicit bounded
JSON object/array/JSONL, text, and binary profiles; exact byte/digest checks;
per-record field presence/kind and literal rules; automatic top-level schema
fingerprints; and signed offline comparison with a separately bound rules input.
No recorded quality rating is changed and no source authority, time coverage, or
collection completeness is inferred. See
[Raw-evidence reassessment](docs/reference/RAW_EVIDENCE_REASSESSMENT_V1.7.md).

Native CloudTrail import/replay is implemented in development: explicit Records
and LookupEvents JSON profiles, strict bounded parsing, exact source/canonical
event digests, retained order and identity distinctions, payload hashes, and
offline signed-case projection comparison. Pagination is reported separately
from unknown overall collection coverage; AWS origin is not authenticated.
See [Native CloudTrail replay](docs/reference/CLOUDTRAIL_REPLAY_V1.7.md).

Google Cloud Audit import/replay is implemented in development: explicit API
response and array profiles, strict bounded parsing, nanosecond timestamp
preservation, separate caller/delegation/permission observations, opaque payload
digests, and offline signed-case comparison. Empty/incomplete exports do not
establish collection completeness; provider origin and human attribution remain
unverified. See [Google Cloud Audit replay](docs/reference/GCP_AUDIT_REPLAY_V1.7.md).

Google Cloud Logging acquisition-context capture is implemented in development:
one fixed entries.list POST, bounded resource/filter/order/page parameters, exact
response preservation, automatic context/projection artifacts, and signed offline
comparison. Empty continuation pages remain incomplete; origin, effective scope,
and pagination-chain coverage remain unverified. See
[Google Cloud capture](docs/reference/GCP_LOGGING_CAPTURE_V1.7.md).

Azure Activity Log import/replay is implemented in development: explicit native
REST response and EventData array profiles, strict bounded parsing, preserved
fractional timestamps, separate invariant/translated labels and identity claims,
opaque payload/continuation digests, and offline signed-case comparison. Recorded
management-plane activity does not prove model invocation, authority, effects, or
complete collection. Log Analytics tables use the separate profile below.
See [Azure Activity Log replay](docs/reference/AZURE_ACTIVITY_REPLAY_V1.7.md).

Log Analytics query-result import/replay is implemented in development: bounded
typed tables, exact row-width checks, ordered column/value bindings, selected
scalar values and opaque cell hashes, preserved partial errors, and offline
signed-case comparison. Rows are not assumed to be raw events, query scope is
unverified, and KQL is never re-executed. The existing Azure collector no longer
marks HTTP success as proof of complete collection.
See [Log Analytics replay](docs/reference/LOG_ANALYTICS_REPLAY_V1.7.md).

Retained Log Analytics request-context binding is implemented in development:
explicit workspace POST and bounded workspace GET profiles, exact response
digest/size checks, separate
signed context artifacts, multi-input lineage validation, and offline projection
comparison. Query text, scope, and selected headers are digest-bound without
inferring effective scope, actual execution, or completeness. See
[Log Analytics context replay](docs/reference/LOG_ANALYTICS_CONTEXT_V1.7.md).

Workspace GET query/timespan binding is implemented in development: strict
single-pass UTF-8 percent decoding, duplicate/ambiguous parameter rejection,
exact URL spelling and order retention, explicit absent-body observations, and
the existing signed offline multi-input replay. The reviewed POST projection
digests are unchanged. See
[Log Analytics GET context](docs/reference/LOG_ANALYTICS_GET_CONTEXT_V1.7.md).

Automatic Log Analytics acquisition-context capture is implemented in development:
an explicit collector option records the prepared workspace POST or GET request and
selected response headers, preserves bounded entity-body bytes before parsing,
and produces context/projection artifacts with an exclusive completion receipt.
Acquisition uses synthetic acceptance; offline replay never initiates a query.
See [Log Analytics capture](docs/reference/LOG_ANALYTICS_CAPTURE_V1.7.md).

Automatic workspace GET capture is implemented in development: an explicit
method option builds the bounded query/timespan URL, checks the actual prepared
request and percent-encoded credential contamination, preserves exact response
bytes, and generates the three signed-replay inputs. Unsupported scope fields,
redirects, and failures never trigger an automatic POST fallback. Default POST
artifact digests remain unchanged. See
[Log Analytics GET capture](docs/reference/LOG_ANALYTICS_GET_CAPTURE_V1.7.md).

Resource-scoped Log Analytics POST/GET binding and capture are implemented in
development: fixed public endpoints, bounded resource identifiers, explicit scope
selection, opaque permission observations, signed offline replay, and unchanged
workspace capture digests. HTTP success remains unknown collection even when
permission metadata is present. See
[Resource-scoped Log Analytics](docs/reference/LOG_ANALYTICS_RESOURCE_V1.7.md).

Form-encoded Log Analytics GET and additional workspace lists are implemented
in development: explicit workspace/resource form profiles, strict plus-before-
percent decoding, bounded GUID lists, exact URL/order binding, automatic capture,
and signed offline replay. Original percent-only GET behavior remains unchanged.
See [Form GET profiles](docs/reference/LOG_ANALYTICS_GET_FORM_V1.7.md).

Lossless Log Analytics numeric replay is implemented in development: exact JSON
number tokens, full signed 64-bit integers, bounded precise decimals and numeric
strings, collision-free typed hashes, signed offline replay, and unchanged
original table hashes. This response-only adapter does not widen capture/context
profiles implicitly. See [Lossless numeric replay](docs/reference/LOG_ANALYTICS_LOSSLESS_V1.7.md).

Verifier-controlled checkpoint key lifecycle is also implemented in development:
active/retired/revoked states, validity windows, tenant/case scope, rotation
overlap, and optional policy digest pinning. See
[Checkpoint key policy](docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md).

External checkpoint anchoring has an implemented RFC 3161 profile: local request
preparation, retained nonce/request binding, independently pinned TSA certificate
and CA trust, offline cryptographic receipt verification, and case/replay gates.
See [Checkpoint timestamps](docs/reference/CHECKPOINT_TIMESTAMPS_V1.7.md).
Acceptance uses an ephemeral synthetic TSA; no external service is deployed.

Authenticated policy packages and persistent revision rollback protection are
implemented in development. An independent issuer signs scoped policies; a
verifier-owned transactional store rejects older/conflicting revisions and
reauthenticates each use. Backup recovery can require an independently retained
revision floor. See [Authenticated policy updates](docs/reference/CHECKPOINT_POLICY_UPDATES_V1.7.md).

Configurable policy issuer quorums are also implemented: distinct Ed25519
co-signatures bind the policy and independently approved issuer configuration.
Partial or conflicting approvals fail, and separate custodians can sign without
sharing private keys. See [Policy issuer quorum](docs/reference/CHECKPOINT_POLICY_QUORUM_V1.7.md).
Custodian independence remains an operator responsibility.

Signed issuer-root rotation and atomic root/policy activation are implemented:
the previous and replacement quorums approve each sequential transition, and a
governed store revalidates the retained chain against an independent root anchor.
Explicit migration preserves policy revision history; current-root checks and
independent recovery floors remain enforced. See
[Signed issuer governance](docs/reference/CHECKPOINT_POLICY_GOVERNANCE_V1.7.md).

Online policy/root delivery has an implemented explicit HTTPS client profile:
bounded authenticated transport, a complete signed chain, atomic catch-up to the
final root/policy, independent recovery floors, and offline verification after
synchronization. Acceptance uses a temporary loopback TLS server and synthetic
CA; no external publisher or scheduled service is deployed. See
[Online policy delivery](docs/reference/CHECKPOINT_POLICY_DELIVERY_V1.7.md).

The policy delivery authentication profile now supports explicit mutual-TLS
client certificates, protected encrypted/unencrypted PKCS8 keys, independent
leaf pins, and bounded local preflight without password prompts. Synthetic
acceptance verifies publisher rejection of unauthenticated clients and preserves
all signed-policy controls. The receipt distinguishes configured credentials
from proof of publisher enforcement. See
[Client certificate authentication](docs/reference/POLICY_DELIVERY_MTLS_V1.7.md).

Controlled policy synchronization scheduling is implemented in development:
operator-owned JSON jobs, independent per-store anchor pins, offline preflight,
explicit single-pass/watch commands, completion-based monotonic deadlines,
bounded backoff/jitter, per-job results, and graceful shutdown. Timing state is
process-local; accepted policy remains persistent. Acceptance uses synthetic
loopback services; deployment and supervision remain operator responsibilities.
See [Policy synchronization scheduling](docs/reference/POLICY_SYNC_SCHEDULING_V1.7.md).

Timestamped historical key-trust records have an implemented bounded profile:
authenticated store capture, complete issuer-chain/policy/checkpoint binding,
independently pinned RFC 3161 receipt verification, and decision replay across
the signed TSA accuracy interval. Current authorization remains a separate
mandatory gate for case use. Acceptance uses a synthetic TSA; global historical
policy completeness and actual prior verifier execution are not proven. See
[Historical key-trust records](docs/reference/CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md).

## Future work

- complete historical policy/revocation and custody evidence beyond the bounded retained-record profile;
- operated policy delivery services, additional deployment identity profiles beyond mTLS, and durable/HA coordination beyond the controlled local scheduling profile;
- independently operated timestamp service deployment, archival TSA revocation evidence, and long-term timestamp renewal;
- additional deterministic parsers and deeper evidence-quality checks beyond the bounded raw-evidence reassessment, recorded gate, native AWS/Google/Azure activity, and Log Analytics profiles, plus authorized live comparison orchestration;

- additional provider-specific raw-export profiles beyond the implemented native parsers, including acquisition-context capture for other providers; implemented numeric/resource/GET profile boundaries are documented in their guides;
- larger PostgreSQL/HA performance qualification across representative enterprise workloads;
- HSM-specific signing profiles and hardware-backed collector keys;
- operated private transparency services, independent witness custody/fork monitoring, and archival log-key governance beyond the implemented offline signed-snapshot/proof profile;
- evidence-source coverage measurement and authoritative provider schema/compatibility evaluation beyond the implemented retained nested-shape comparisons;
- additional independent visible-rendering adapters for representation attacks;
- full investigation modeling, bidirectional import, and external case-management interoperability beyond the implemented optional CASE/UCO 1.5.0 inventory view;
- broader hostile document/format corpora, persistent fuzz corpus curation, structure-aware mutation, and native sanitizer qualification beyond the implemented finite and coverage-guided provider/archive campaigns;
- external independent penetration-test reports and deployment certifications when a production environment exists.

Roadmap items are not treated as implemented evidence capabilities until code, Evidence Packs, analyst documentation, and acceptance tests are present.
