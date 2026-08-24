# AI-DFIR v1.6.0 — Production Assurance & Hardened Enterprise Deployment

v1.6 closes the remaining gap between a production-capable reference platform
and an evidence-backed production deployment model.

## Added

- continuous Platform Assurance state;
- provider/API certification with expiry;
- lab/staging/production trust-domain separation;
- controlled failover/chaos validation;
- release checksum/SBOM/SLSA integrity gates;
- independent security-assessment gate;
- upgrade/rollback assurance;
- transactional schema migrations with checksum protection;
- production Helm chart and default-deny policies;
- digest-only production Docker build;
- container signing/provenance GitHub workflows;
- OPA-style production image admission policy;
- 15 production-assurance Evidence Packs;
- Production Platform Assurance Workbench panel;
- final v1.6 production-readiness gate.

## Evidence Packs

Total catalog: **111**.

## Important boundary

v1.6 can validate production-control evidence, but it cannot substitute for the
organization actually deploying HA PostgreSQL, immutable storage, KMS/HSM,
enterprise identity, workload identity or independent security testing.

## Demo and training assets

- added a 91-second captioned synthetic-data demo video under `docs/demo/AI-DFIR-v1.6.0-demo.mp4`;
- added `scripts/generate_demo_case.py` for a reproducible Workbench case;
- added `scripts/make_demo_video.py` and `docs/demo/DEMO_SCRIPT.md`;
- demo content uses bundled synthetic fixtures only.
