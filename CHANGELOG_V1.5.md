# v1.5 Changelog — Distributed Enterprise AI-DFIR & Production Collectors

## Enterprise metadata and tenancy

- durable tenant/case/evidence/task/collector/legal-hold metadata;
- PostgreSQL production schema with row-level-security policies and FORCE RLS;
- SQLite retained as single-node/reference backend;
- collector enrollment required before distributed task leasing.

## Enterprise identity

- historical OIDC/JWT evaluation with tenant RBAC;
- SPIFFE/X.509-SVID validation with incident-time CRL evaluation;
- signed normalized identity envelope for hardened SAML/OIDC gateways;
- authenticated enterprise metadata gateway.

## Protected evidence custody

- streamed per-object envelope encryption;
- AWS KMS, Azure Key Vault, Google Cloud KMS and local-test KEK adapters;
- immutable object-store abstraction with S3 Object Lock support;
- protected ingest path that stores ciphertext rather than plaintext;
- signed legal-hold lifecycle plus storage-level hold enforcement;
- signed DR manifests and restore validation;
- signed tenant-bound case exports and verification.

## Distributed/provider collection

- signed acquisition requests and collector receipts;
- allowlisted collector execution only;
- provider-native collection for Microsoft Graph Security/Foundry, OpenAI,
  Anthropic, AWS Bedrock/CloudTrail, Google Cloud Logging, GitHub Copilot, and
  local Claude Code/Cursor artifacts;
- pagination-aware collection and explicit completion metadata;
- provider evidence-gap analysis.

## Operations

- service SLO assessment;
- reference/deployment scale benchmarking;
- fail-closed production-readiness gate;
- analyst action audit, peer review, redaction, exports, and transparency
  evidence inherited from v1.4.

## Release hardening

- optional PyMuPDF dependency removed from the default profile due to its
  AGPL/commercial licensing boundary;
- v1.5 legal-hold storage enforcement added to the acceptance test;
- GitHub community/security files, CI templates, deployment guides, analyst/HITL
  manuals, and synthetic test-log corpus added.
