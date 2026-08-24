# v1.4 Recommendation Implementation Matrix

| Recommendation | v1.4 implementation | Result |
|---|---|---|
| Workload identity / SPIFFE | `workload_identity.py` | incident-time SVID/workload/selector analysis |
| Credential lineage | `credential_lineage.py` | exchange, audience, scope, expiry/revocation, workload reuse |
| Temporal effective authority | `temporal_authority.py` | grants, denies, tenant/resource/purpose, approval and credential-time checks |
| Persistent memory integrity | `memory_integrity_v2.py` | signed snapshots, versions, TTL, tombstones, tenant/source/vector lineage |
| Skill supply-chain | `skill_supply_chain.py` | Merkle manifest, signing, executable/content/endpoint/capability drift |
| Full MCP 2026-07-28 coverage | `mcp_forensics_v14.py` | routing headers, OAuth/issuer/PKCE/PRM, caches, Tasks, MRTR, Apps |
| Native OTel GenAI ingestion | `otel_genai_ingest.py` | trace/span → normalized agentic events, hash-only content default |
| Typed causal graph | `causal_graph_v2.py` | typed evidence edges and claim-path validation |
| Collector/retention health | `collector_health.py` | evidence availability, coverage, retention and clock gaps |
| External transparency | `transparency_anchor_v14.py` | signed offline submission bundles and receipt/inclusion verification |
| Detection validation lab | `detection_validation_lab.py` | manifest-driven regression suite without arbitrary shell execution |
| Safe behavioral detonation | `behavioral_sandbox.py` | external canary policy + declared-vs-observed telemetry analysis; no suspect execution |
| Provider-native collection path | `provider_normalizer.py`, `provider_collection_profiles.json` | reference normalization profiles for major providers; no hidden API polling |
| SOC productization controls | `analyst_action_audit.py`, `peer_review_gate.py`, `evidence_redaction.py`, `integration_export.py` | signed analyst audit, independent review, traceable redaction, ECS/STIX export |
| Production infrastructure gate | `production_readiness.py` | refuses production-ready status without HA DB, real IdP, mTLS/SPIFFE, KMS/HSM, immutable storage, tenant isolation, DR, audit/review |

## Important boundary

v1.4 provides reference integrations and validation contracts. It does **not** pretend to deploy an organization's PostgreSQL cluster, OIDC provider, KMS/HSM, object-lock bucket, SPIRE infrastructure or external transparency service. `production_readiness.py` makes those missing deployment controls visible rather than silently claiming enterprise readiness.
