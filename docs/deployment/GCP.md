# Google Cloud Deployment Mapping

- Metadata: approved HA PostgreSQL.
- Evidence: retention-locked/versioned object storage.
- KEK: Cloud KMS through the `google_cloud_kms` adapter.
- Identity: OIDC/IAP or enterprise gateway plus workload identity/mTLS.
- Collection: Cloud Logging/Audit Logs for Vertex/Gemini and surrounding IAM,
  network, and workload telemetry.
