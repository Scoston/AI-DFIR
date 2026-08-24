# Kubernetes Reference Deployment

The manifests in `deploy/kubernetes/` are starting points, not a turnkey chart.
Use non-root containers, read-only root filesystems, default-deny NetworkPolicy,
secret-store/CSI key integration, workload identity/SPIFFE, external HA
PostgreSQL, immutable object storage, resource limits, and admission policy.

Do not mount production case evidence into the Workbench as a writable volume.
