# AI-DFIR Helm chart

This chart intentionally does **not** deploy PostgreSQL, KMS or an evidence object store. Production deployments should use organization-managed HA services and inject only references/identity through the platform secret/identity system.

The chart uses digest-pinned images, non-root execution, read-only root filesystem, dropped Linux capabilities, RuntimeDefault seccomp, PDB, three replicas, and default-deny network policy. Adapt the egress policy to exact PostgreSQL/object-store/KMS/IdP endpoints before deployment.
