# Remaining roadmap qualification requirements (development)

Development changes are committed and checked independently of release or
deployment promotion. The current representation work includes bounded archive,
DOCX, HTML/CSS, text/PDF/font and two-source comparison entry points; fixed
coverage-guided targets; and a pinned persistent synthetic corpus. These controls
do not turn the remaining production or external-validation items into completed
capabilities.

## Next selected item: independent visible rendering

The next representation item is an independently sourced rendering/text adapter,
with original-byte binding, renderer/version identity, bounded resource handling,
and explicit partial/failed observations. The bounded comparator can consume
retained text observations, but cannot establish how they were rendered.

Qualification needs a disposable Linux host with working process/network/mount
isolation and a selected renderer/OCR profile. In this development session,
Poppler's `pdftoppm` and Tesseract were present, while Chromium, LibreOffice,
Docker, and Clang were absent. A harmless Bubblewrap namespace probe did not
complete within ten seconds. This is insufficient evidence of usable isolation;
no uncontained renderer run was promoted as a qualified adapter.

On an appropriate host, acceptance must demonstrate controlled source mounts,
network denial, bounded pages/pixels/output/time/memory, actual independent output,
source/renderer bindings, and explicit behavior for unsupported, hidden, corrupt,
and resource-exhausting inputs. Synthetic successes alone must not claim complete
visible content, authentic sources, or production deployment certification.

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
| Independent visible rendering | Bounded static intake and two-source comparison | Qualified isolated renderer/OCR host and the acceptance described above |
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
