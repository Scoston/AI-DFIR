# Remaining roadmap qualification requirements (development)

Development changes are committed and checked independently of release or
deployment promotion. The current representation work includes bounded archive,
DOCX, HTML/CSS, text/PDF/font and two-source comparison entry points; fixed
coverage-guided targets; and a pinned persistent synthetic corpus. These controls
do not turn the remaining production or external-validation items into completed
capabilities.

## Independent visible rendering: bounded PDF and grayscale PNG profiles

The optional [isolated PDF adapter](ISOLATED_PDF_RENDERING_V1.7.md) renders
bounded grayscale pages and English OCR through an explicitly pinned local Docker
image. A dedicated GitHub workflow qualifies twelve synthetic PDF cases on an
Ubuntu 24.04 Docker host. Ten must render successfully: baseline visible text,
hidden machine text, two pages, blank output, white-on-white source text, off-page
source text, clipped source text, two-column layout, 90-degree page rotation, and
the four-page upper boundary. Malformed and five-page inputs must remain
unavailable. The workflow also checks kernel isolation observations,
source/image/text bindings, representation divergence, failure handling, and
cleanup. Its retained observations qualify only the tested image and profile.

The [bounded PNG OCR bridge](PNG_OCR_BRIDGE_V1.7.md) extends that same isolated
renderer to one additional visible-input profile without introducing a host-native
image decoder. The host first applies the existing strict 8-bit grayscale PNG
validator, then embeds the exact validated IDAT stream in a deterministic one-page
PDF image object. The original PNG identity and the derived bridge-PDF identity
remain separately bound. The renderer workflow requires actual acceptance of a
high-contrast synthetic text image and a blank image, and requires malformed and
RGB PNGs to fail before native execution. Those cases qualify only the narrow
grayscale profile and the tested renderer image; they do not establish arbitrary
PNG compatibility or OCR accuracy.

The earlier local namespace probe remains insufficient for local isolation
qualification. Neither adapter falls back to an uncontained host renderer.
Ordinary source/extracted tests use synthetic protocol replies and explicitly
cannot claim native rendering. No production deployment or complete visible
content, OCR accuracy, or source authenticity is established.

The curated representation-hostile PDF cases cover four source-versus-visible
failure modes: render-mode hidden text, white-on-white text, off-page text, and
clipped text are checked through the same comparison path. The PNG bridge adds a
separate original-versus-derived custody path for a bounded visible image source.
Remaining rendering work covers JPEG and other named formats, color/alpha image
profiles, additional OCR languages, broader layouts/fonts, larger hostile corpora,
native sanitizers, and production host/image qualification. Each needs concrete
fixtures and actual acceptance on its target runtime. The existing comparator can
consume a retained OCR observation without automatically promoting evidence-gate
decisions.

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
| Broader visible rendering | Isolated bounded PDF/English OCR plus strict grayscale-PNG bridge, curated source-vs-visible PDF cases, rotation/two-column layout, static intake and two-source comparison | Selected additional formats/languages/layouts/fonts, color/alpha profiles, larger curated fixtures, native sanitizer profile, and actual target-host qualification |
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
