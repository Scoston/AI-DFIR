# AI-DFIR Documentation

## Start here

- [Installation](../INSTALL.md)
- [Testing](../TESTING.md)
- [v1.6 Runbook](../V1.6_RUNBOOK.md)
- [Production Readiness](../PRODUCTION_READINESS_V1.6.md)
- [Platform Assurance](../PLATFORM_ASSURANCE_V1.6.md)
- [v1.7 Offline Verification](reference/OFFLINE_VERIFICATION_V1.7.md)
- [v1.7 Release Assurance](reference/RELEASE_ASSURANCE_V1.7.md)
- [Native CloudTrail Import and Replay (development)](reference/CLOUDTRAIL_REPLAY_V1.7.md)
- [Google Cloud Audit Import and Replay (development)](reference/GCP_AUDIT_REPLAY_V1.7.md)
- [Azure Activity Log Import and Replay (development)](reference/AZURE_ACTIVITY_REPLAY_V1.7.md)
- [Log Analytics Query-result Import and Replay (development)](reference/LOG_ANALYTICS_REPLAY_V1.7.md)
- [Log Analytics Retained Request Context and Replay (development)](reference/LOG_ANALYTICS_CONTEXT_V1.7.md)
- [Automatic Log Analytics Acquisition-context Capture (development)](reference/LOG_ANALYTICS_CAPTURE_V1.7.md)
- [Demo](demo/README.md)

## Analyst

See [`analyst/README.md`](analyst/README.md) for investigation workflow, evidence quality, causality, containment, reporting, false positives, provider evidence, representation integrity, A2A/MCP, identity/authority, and human-in-the-loop guidance.

## Deployment

See [`deployment/README.md`](deployment/README.md) for standalone, Kubernetes, AWS, Azure, GCP, air-gapped, identity, provider collectors, hardening, Object Lock/legal hold, HA/DR, upgrades, and production architecture.

## Operations

The [`operations/`](operations/) directory covers collector enrollment, provider certification, platform assurance, key rotation, backup/restore, failover/chaos drills, SLOs, and release operations.

## Reference

The [`reference/`](reference/) directory contains CLI/event/log schemas, Evidence Pack catalog, provider capability matrix, test scenario catalog, GitHub release guidance, security model, offline-verification guidance, release-assurance guidance, and glossary.
