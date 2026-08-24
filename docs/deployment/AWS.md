# AWS Deployment Mapping

- Metadata: RDS/Aurora PostgreSQL with an application role that cannot bypass RLS.
- Evidence: S3 with versioning and Object Lock enabled.
- KEK: AWS KMS customer-managed key with CloudTrail auditing.
- Collectors: read-only IAM roles for CloudTrail, Bedrock, and related sources.
- Identity: OIDC for analysts and workload identity/SPIFFE/mTLS for collectors.

AI-DFIR includes AWS KMS and S3 Object Lock adapters. Test them in a staging
account before production use.
