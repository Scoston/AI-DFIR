# v1.0 Changelog — Enterprise AI Incident Response Platform

Added:
- enterprise case lifecycle database
- case membership and assignment
- tenant-aware case isolation
- RBAC permission model
- classification-aware evidence access
- SSO/reverse-proxy trusted auth context
- encrypted content-addressed evidence repository
- SHA-256 deduplication
- AES-256-GCM optional at-rest encryption
- repository audit hash chain
- legal hold
- retention/disposition planning
- signed repository integrity checkpoints
- distributed collector registry
- tenant-bound Ed25519 collector evidence bundles
- verified central evidence ingest
- repository-to-workbench case materialization
- Evidence Pack-driven acquisition tasks
- signed detection/evidence content releases
- enterprise case-management API
- read-only enterprise portal
- OCSF 1.8 Incident Finding export
- Splunk HEC envelope export
- signed generic webhook export
- neutral case interchange
- closure-readiness gate
- single-node systemd/Docker reference deployment

Retained:
- all v0.1-v0.9 model, behavioral, agentic, evidence-pack, workbench,
  containment and forensic-reconstruction capabilities.
