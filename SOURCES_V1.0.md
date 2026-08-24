# v1.0 Standards Sources

Verified 2026-08-23.

## OCSF 1.8.0
https://github.com/ocsf/ocsf-schema/releases

The March 2026 OCSF 1.8.0 release is the current published release used by
v1.0. Relevant additions include:
- ai_operation profile
- ai_model
- message_context
- token
- gpu_info
- privilege_info

OCSF Incident Finding exists in the Findings category and is used by
`enterprise_exports.py`.

## NIST AI 800-4
https://www.nist.gov/publications/challenges-monitoring-deployed-ai-systems-center-ai-standards-and-innovation

Published March 6, 2026. v1.0's continuous/fleet monitoring and evidence
sufficiency design is consistent with the report's emphasis on post-deployment
visibility, variability and unforeseen real-world consequences.

## OpenTelemetry semantic conventions
https://opentelemetry.io/docs/specs/otel/semantic-conventions/

OpenTelemetry is used as an observability integration surface. The semantic
conventions remain an evolving specification and are not treated as the
forensic source of record.
