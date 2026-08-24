# Enterprise Reference Deployment

## Recommended topology

```text
Analysts
   |
OIDC/SAML Gateway ---- signed analyst audit
   |
Metadata API / Workbench
   |
PostgreSQL HA  <---->  Immutable/WORM Object Store
   |                         |
Tenant RLS                 KMS/HSM
   |
Acquisition Queue
   |
SPIFFE/mTLS collectors ---- provider APIs / endpoints / clusters
```

## Required production controls

- PostgreSQL with backups, replication/HA appropriate to the service tier, and
  AI-DFIR RLS policies applied.
- Immutable object storage such as S3 Object Lock COMPLIANCE or equivalent WORM.
- KMS/HSM-backed KEK management; `local-test` KEK is prohibited for production.
- OIDC with pinned issuer/JWKS policy or a hardened SAML/OIDC gateway producing
  signed normalized identity envelopes.
- mTLS/SPIFFE identity for distributed collectors.
- network allowlists restricting collectors to required provider endpoints.
- provider API service principals with read-only scopes.
- signed analyst actions, independent peer review, redaction validation, DR
  restore validation, and legal-hold capability.

## Metadata database

Apply `postgres_schema_v15.sql`. AI-DFIR sets `app.tenant_id` inside tenant
transactions. Verify RLS from a non-owner application role; do not run the API as
PostgreSQL superuser or table owner if that would bypass policy.

## Evidence ingest

```bash
python enterprise_evidence_ingest_v15.py   --src /acquisition/raw/evidence.json   --tenant ACME   --case IR-2026-001   --dsn "$AIDFIR_POSTGRES_DSN"   --kek-json /etc/ai-dfir/kms.json   --store-json /etc/ai-dfir/object-store.json   --classification restricted   --out ingest-receipt.json
```

This path hashes plaintext, envelope-encrypts it with a per-object DEK, stores
ciphertext in immutable storage, and commits tenant/case metadata.
