# Roadmap

## Current release: v1.6.0

v1.6.0 delivers production-assurance controls on top of the model, runtime, agent, representation, A2A, stateful-agent, and distributed-enterprise layers. The current release includes evidence-backed platform assurance, provider certification, environment separation, chaos/failover result evaluation, hardened Kubernetes/container deployment patterns, release integrity/provenance controls, upgrade/rollback assurance, independent security-assessment gates, and 111 Evidence Packs.

## Future work

- additional provider-specific raw-export parsers as vendors expose telemetry;
- larger PostgreSQL/HA performance qualification across representative enterprise workloads;
- HSM-specific signing profiles and hardware-backed collector keys;
- private transparency-log implementations and multi-party evidence anchoring;
- more automatic evidence-source coverage measurement and provider schema-change detection;
- additional independent visible-rendering adapters for representation attacks;
- optional standards-based case exchange profiles beyond the current neutral/STIX/ECS exports;
- broader fuzzing and hostile-file corpora for parsers and archive/document intake;
- external independent penetration-test reports and deployment certifications when a production environment exists.

Roadmap items are not treated as implemented evidence capabilities until code, Evidence Packs, analyst documentation, and acceptance tests are present.
