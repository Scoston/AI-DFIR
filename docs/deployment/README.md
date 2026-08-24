# Deployment Guides

Choose the guide that matches the deployment maturity:

1. `LAB_STANDALONE.md` — one analyst workstation, local case/evidence paths.
2. `ENTERPRISE_REFERENCE.md` — PostgreSQL, immutable object storage, KMS,
   authenticated gateway, distributed collectors.
3. `KUBERNETES.md` — reference Kubernetes topology and hardening requirements.
4. `AWS.md`, `AZURE.md`, `GCP.md` — provider-specific control mappings.
5. `AIR_GAPPED.md` — offline evidence transfer and dependency staging.
6. `IDENTITY.md` — OIDC, SPIFFE/mTLS, signed gateway identity.
7. `HA_DR.md` — backup, restore validation, SLO, and disaster recovery.
8. `OBJECT_LOCK_AND_LEGAL_HOLD.md` — retention and hold enforcement.
9. `PROVIDER_COLLECTORS.md` — provider-native collection configuration.
10. `PRODUCTION_READINESS.md` — evidence-backed go-live gate.
11. `HARDENING.md` — least privilege, egress, secrets, audit, and host controls.
12. `UPGRADE_ROLLBACK.md` — release migration and rollback procedure.

All production examples are reference patterns. Run `production_readiness_v16.py` against your environment and review the resulting evidence with the responsible human approvers before calling a deployment production ready.
