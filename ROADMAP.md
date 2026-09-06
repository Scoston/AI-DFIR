# Roadmap

## Current release: v1.7.0

v1.7.0 adds signed investigation checkpoints, offline case verification, and
committed-source release assurance to the earlier production-assurance controls.
The current catalog contains 111 Evidence Packs.

## Implemented in development, unreleased

Investigation provenance/reference validation, evidence lineage validation,
recorded AI/tool/analyst reconstruction, preserved-execution comparison, and two
pure deterministic replay adapters. See
[Investigation replay](docs/reference/INVESTIGATION_REPLAY_V1.7.md) for the
implemented profile and acceptance requirements.

Verifier-controlled checkpoint key lifecycle is also implemented in development:
active/retired/revoked states, validity windows, tenant/case scope, rotation
overlap, and optional policy digest pinning. See
[Checkpoint key policy](docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md).

## Future work

- authenticated checkpoint-policy distribution and independently timestamped historical key-trust decisions;
- external checkpoint anchoring and independently operated timestamp services;
- additional deterministic parser/Evidence Pack replay adapters and authorized live comparison orchestration;

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
