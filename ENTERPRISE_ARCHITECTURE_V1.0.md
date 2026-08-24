# AI-DFIR v1.0 Enterprise Architecture

## Trust domains

```text
                     ENTERPRISE IDENTITY
                           OIDC/SAML/MFA
                               |
                               v
                  Identity-aware reverse proxy
                  signed short-lived auth context
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
       Enterprise API                    Enterprise Portal
       case workflow                     read-only metadata
              |                                 |
              +----------------+----------------+
                               |
                    CASE / POLICY DATABASE
                               |
                               v
                    EVIDENCE REPOSITORY
                  content-addressed SHA-256
               optional AES-256-GCM at rest
                               ^
                               |
              +----------------+----------------+
              |                                 |
        signed collector                  manual/case ingest
        evidence bundles                  verified acquisition
              ^
              |
       distributed sensors
       cloud / endpoint / AI
       MCP / RAG / model / agent

                               |
                               v
                   Authorized materialization
                               |
                               v
                     v0.9 Analyst Workbench
                     read-only investigation
                               |
          +--------------------+--------------------+
          |                    |                    |
       Evidence             Containment          Reporting
       Packs                v0.6                 OCSF 1.8
       v0.8/v0.9            controls             signed exports
```

## Evidence source of record

The enterprise repository is the source of record.

A materialized analyst workspace is a derived working copy. Every exported
artifact retains its repository evidence ID, original SHA-256, classification,
source and logical name in `REPOSITORY_EXPORT_MANIFEST.json`.

## Authentication

AI-DFIR v1.0 does not implement an identity provider.

Production identity is expected to be established by an enterprise
identity-aware reverse proxy. The proxy maps directory groups to AI-DFIR RBAC
roles and signs short-lived authorization claims.

The API verifies the signed claims on every request.

## Authorization roles

```text
viewer
analyst
senior_analyst
incident_commander
evidence_custodian
auditor
admin
```

Evidence has one of:

```text
public
internal
confidential
restricted
secret
```

Role clearance is applied before evidence metadata or materialized evidence is
returned.

## Repository integrity

Evidence identity:

```text
SHA-256(original plaintext bytes)
```

Storage:

```text
objects/sha256/<first-two>/<digest>
```

Optional encryption:

```text
AES-256-GCM
AAD = plaintext SHA-256
```

The repository also preserves a chained audit log.

Periodic repository checkpoints can be Ed25519 signed and exported into a
different trust domain/WORM store.

## Multi-tenancy

Cases have a tenant ID.

Controls exist at multiple boundaries:

- API prevents cross-tenant case access.
- collectors are explicitly authorized for tenant IDs.
- collector bundles cryptographically bind tenant ID + case ID + file hashes.
- ingest verifies bundle tenant equals enterprise case tenant.
- case IDs are globally unique.

## Distributed collection

Collectors do not receive repository write access.

They create signed evidence bundles containing:

```text
collector identity
tenant ID
case ID
bundle ID
creation timestamp
logical artifact name
classification
relative bundle path
size
SHA-256
```

The central ingest process verifies identity and all object hashes before CAS
ingestion.

## Evidence Pack control plane

Evidence and detection content is independently releaseable.

`content_pack_manager.py` signs:

- evidence packs
- Microsoft alert mappings
- Agentic Top-10 mappings
- deterministic agentic rules
- provider capability definitions
- schema documentation

This allows controlled promotion from development -> staging -> production.

## SOC integration

v1.0 retains OCSF AI operation exports and adds OCSF 1.8 Incident Finding
exports for case workflow.

It also emits:

- Splunk HEC-compatible event envelopes
- signed generic webhook event files
- neutral case-interchange JSON

Transport to a SIEM/SOAR remains an environment-specific integration because
credentials, proxies, API endpoints and approval policy vary by organization.

## Closure

The closure gate checks:

```text
mandatory Evidence Pack sufficiency
unsupported conclusion gates
open downstream consequences
containment state
repository integrity
```

A finding being quiet is not evidence that the incident is resolved.
