# High Availability and Disaster Recovery

Use PostgreSQL replication/HA appropriate to RPO/RTO and back up metadata
separately from immutable evidence objects. Replicate evidence while preserving
object/version identity and retention controls.

A backup job status is not sufficient. Use `dr_integrity_v15.py` to create a
signed backup manifest and validate a restored copy hash-for-hash. The production
readiness gate should require a recent restore validation timestamp.
