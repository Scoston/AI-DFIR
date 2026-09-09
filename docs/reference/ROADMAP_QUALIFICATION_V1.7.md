# Remaining roadmap qualification requirements (development)

Development changes are committed and checked independently of release or
deployment promotion. The current representation work includes bounded archive,
DOCX, HTML/CSS, text/PDF/font and two-source comparison entry points; fixed
coverage-guided targets; and a pinned persistent synthetic corpus. These controls
do not turn the remaining production or external-validation items into completed
capabilities.

## Independent visible rendering: bounded PDF profile implemented

The optional [isolated PDF adapter](ISOLATED_PDF_RENDERING_V1.7.md) now renders
bounded grayscale pages and English OCR through an explicitly pinned local Docker
image. A dedicated GitHub workflow qualifies six synthetic cases on an Ubuntu
24.04 Docker host, including kernel isolation observations, source/image/text
bindings, hidden-text exclusion and divergence, failure handling, and cleanup.
Its retained observations qualify only the tested image and profile.

The earlier local namespace probe remains insufficient for local isolation
qualification. The adapter does not fall back to an uncontained host renderer.
Ordinary source/extracted tests use synthetic protocol replies and explicitly
cannot claim native rendering. No production deployment or complete visible
content, OCR accuracy, or source authenticity is established.

Remaining rendering work covers named additional formats, languages and layouts,
curated hostile raster/OCR cases, native sanitizers, and production host/image
qualification. Each needs concrete fixtures and actual acceptance on its target
runtime. The existing comparator can consume a retained OCR observation without
automatically promoting evidence-gate decisions.

## Remaining work and concrete inputs

| Roadmap area | Existing foundation | Needed to complete the next qualification |
|---|---|---|
| Historical policy, revocation, custody | Bounded timestamped trust records and signed governance | Retained authoritative custody/revocation sources, archival policy, and a defined verification interval |
| Operated policy delivery and durable/HA scheduling | Authenticated HTTPS/mTLS delivery and controlled local scheduler | Staging service topology, durable coordination target, identities, and restart/failover acceptance |
| Operated TSA and long-term renewal | Offline RFC 3161 verification with synthetic TSA acceptance | Selected TSA service/trust anchors, archival revocation records, retention and renewal policy |
| Additional parsers, deeper quality checks, live comparisons | Twelve fixed replay adapters and retained raw-evidence/schema checks | A specified export/API version, permissible synthetic fixtures, forensic proposition, and authorized live target for live acceptance |
| Additional provider exports/acquisition context | Native AWS/Google/Azure replay and bounded Google/Log Analytics capture | Selected provider operation/scope, exact request/response contract and fixtures; live credentials stay outside the repository |
| PostgreSQL/HA performance | Existing readiness, isolation, and drill evaluation | Representative staging dataset/workload, SLOs, topology, and measured load/failover results |
| HSM signing and hardware collector keys | Existing signed checkpoints, scoped trust, and key governance | Specific HSM/KMS/PKCS#11 interface, accessible test hardware, key policy and failure/rotation acceptance |
| Operated transparency and witnessing | Offline signed states, inclusion/consistency proofs, witness keys | Independent service/custodian topology, retained prior heads, fork-monitor and archival-key operation |
| Source coverage and authoritative compatibility | Retained schema-shape comparisons and explicit unknown collection | Authoritative source inventory, effective scope/retention evidence, versioned provider contracts and reference populations |
| Broader visible rendering | Isolated bounded PDF/English OCR profile, static intake and two-source comparison | Selected additional formats/languages/layouts, curated synthetic fixtures, and actual target-host qualification |
| Full CASE/UCO investigation/import interoperability | Verified inventory/lineage export and official schema validation | Named external system/version, mapping and loss policy, representative synthetic bidirectional fixtures |
| Broader corpora, grammar mutation, native sanitizers | Twenty-three fuzz profiles, three structure-preserving targets, eight curated cases | Selected additional formats and grammars, curated synthetic inputs, reproducible sanitizer toolchain and actual native campaign evidence |
| Independent penetration testing/certification | Threat model, negative tests, release assurance and readiness gates | A deployed assessment target, independent assessor, agreed scope and retained report |

No live cloud acquisition, production deployment, external assessment, release tag,
or service qualification is represented by the repository's local acceptance runs.
The operator supplies target-specific configuration and access through their
approved environment. Credentials and customer evidence must not be committed.
Each remaining capability should be marked complete only after its code, analyst
interpretation, and actual acceptance evidence exist; an unavailable environment
or unspecified external contract remains an open item.

See [Roadmap](../../ROADMAP.md), [Production readiness](../../PRODUCTION_READINESS_V1.6.md),
and [Bounded comparison](BOUNDED_REPRESENTATION_COMPARISON_V1.7.md).
