# AI-DFIR Threat Model

AI-DFIR processes evidence that may be actively adversarial. The platform must
assume that models, documents, logs, agent memory, tool metadata, provider
responses, and even collector hosts can be compromised.

## Protected assets

- original evidence and hashes;
- acquisition receipts and chain of custody;
- case metadata and tenant boundaries;
- signing/private keys and KMS material;
- identity/trust policy;
- analyst conclusions and peer review;
- legal holds and retention state.

## Primary adversaries

- attacker controlling an AI input/document;
- compromised model/adapter/runtime;
- malicious or compromised MCP/A2A/tool server;
- malicious skill or workspace package;
- compromised collector/workload;
- tenant attempting cross-tenant access;
- attacker modifying provider exports or local logs;
- insider attempting to alter evidence or closure state.

## Key controls

- raw-evidence preservation before normalization;
- SHA-256 and signed acquisition/trust records;
- tenant-scoped metadata plus PostgreSQL RLS;
- per-object envelope encryption and immutable storage;
- offline-first key/trust evaluation;
- fail-closed unsupported/missing evidence semantics;
- deterministic content intake for adversarial files;
- read-only analyst Workbench;
- separate signed analyst annotations/review;
- explicit collection-health and retention-gap evidence.

## Non-goals

AI-DFIR is not an EDR, malware detonation service, autonomous offensive agent,
or arbitrary remote-administration framework. Provider APIs and infrastructure
must be configured and authorized by the deploying organization.
