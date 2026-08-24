# Reference deployment limits

The included Docker Compose / systemd profiles are deliberately single-node.

They are suitable for:
- lab validation,
- design review,
- controlled pilot environments.

Before production at enterprise scale, replace or augment:
- SQLite with an HA transactional database,
- local CAS with replicated immutable/object-lock storage,
- environment-file secrets with KMS/HSM/secrets manager,
- direct local ports with an identity-aware TLS reverse proxy,
- local backup with tested cross-account/cross-region backup,
- local audit checkpoints with external/WORM anchoring.

Do not interpret "v1.0" as a claim that these reference deployment primitives
alone satisfy an organization's HA, compliance, or disaster-recovery requirements.
