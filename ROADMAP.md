# Roadmap

## Current release: v1.7.0

v1.7.0 adds signed investigation checkpoints, offline case verification, and
committed-source release assurance to the earlier production-assurance controls.
The current catalog contains 111 Evidence Packs.

## Implemented in development, unreleased

Investigation provenance/reference validation, evidence lineage validation,
recorded AI/tool/analyst reconstruction, preserved-execution comparison, and
four fixed deterministic replay adapters: RFC 8785, legacy provider normalization,
recorded Evidence Pack gates, and native CloudTrail projection. See
[Investigation replay](docs/reference/INVESTIGATION_REPLAY_V1.7.md) for the
implemented profile and acceptance requirements.

Evidence Pack conclusion-gate replay is implemented in development: retained pack
rules, complete recorded quality states, canonical pack binding, strict bounded
inputs, and offline comparison within signed case reconstruction. Its pure gate
calculation is shared with the assessment engine. All 111 current catalog packs
fit the profile; raw evidence quality is not reassessed or implicitly approved.
See [Evidence Pack gate replay](docs/reference/EVIDENCE_PACK_REPLAY_V1.7.md).

Native CloudTrail import/replay is implemented in development: explicit Records
and LookupEvents JSON profiles, strict bounded parsing, exact source/canonical
event digests, retained order and identity distinctions, payload hashes, and
offline signed-case projection comparison. Pagination is reported separately
from unknown overall collection coverage; AWS origin is not authenticated.
See [Native CloudTrail replay](docs/reference/CLOUDTRAIL_REPLAY_V1.7.md).

Verifier-controlled checkpoint key lifecycle is also implemented in development:
active/retired/revoked states, validity windows, tenant/case scope, rotation
overlap, and optional policy digest pinning. See
[Checkpoint key policy](docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md).

External checkpoint anchoring has an implemented RFC 3161 profile: local request
preparation, retained nonce/request binding, independently pinned TSA certificate
and CA trust, offline cryptographic receipt verification, and case/replay gates.
See [Checkpoint timestamps](docs/reference/CHECKPOINT_TIMESTAMPS_V1.7.md).
Acceptance uses an ephemeral synthetic TSA; no external service is deployed.

Authenticated policy packages and persistent revision rollback protection are
implemented in development. An independent issuer signs scoped policies; a
verifier-owned transactional store rejects older/conflicting revisions and
reauthenticates each use. Backup recovery can require an independently retained
revision floor. See [Authenticated policy updates](docs/reference/CHECKPOINT_POLICY_UPDATES_V1.7.md).

Configurable policy issuer quorums are also implemented: distinct Ed25519
co-signatures bind the policy and independently approved issuer configuration.
Partial or conflicting approvals fail, and separate custodians can sign without
sharing private keys. See [Policy issuer quorum](docs/reference/CHECKPOINT_POLICY_QUORUM_V1.7.md).
Custodian independence remains an operator responsibility.

Signed issuer-root rotation and atomic root/policy activation are implemented:
the previous and replacement quorums approve each sequential transition, and a
governed store revalidates the retained chain against an independent root anchor.
Explicit migration preserves policy revision history; current-root checks and
independent recovery floors remain enforced. See
[Signed issuer governance](docs/reference/CHECKPOINT_POLICY_GOVERNANCE_V1.7.md).

Online policy/root delivery has an implemented explicit HTTPS client profile:
bounded authenticated transport, a complete signed chain, atomic catch-up to the
final root/policy, independent recovery floors, and offline verification after
synchronization. Acceptance uses a temporary loopback TLS server and synthetic
CA; no external publisher or scheduled service is deployed. See
[Online policy delivery](docs/reference/CHECKPOINT_POLICY_DELIVERY_V1.7.md).

The policy delivery authentication profile now supports explicit mutual-TLS
client certificates, protected encrypted/unencrypted PKCS8 keys, independent
leaf pins, and bounded local preflight without password prompts. Synthetic
acceptance verifies publisher rejection of unauthenticated clients and preserves
all signed-policy controls. The receipt distinguishes configured credentials
from proof of publisher enforcement. See
[Client certificate authentication](docs/reference/POLICY_DELIVERY_MTLS_V1.7.md).

Controlled policy synchronization scheduling is implemented in development:
operator-owned JSON jobs, independent per-store anchor pins, offline preflight,
explicit single-pass/watch commands, completion-based monotonic deadlines,
bounded backoff/jitter, per-job results, and graceful shutdown. Timing state is
process-local; accepted policy remains persistent. Acceptance uses synthetic
loopback services; deployment and supervision remain operator responsibilities.
See [Policy synchronization scheduling](docs/reference/POLICY_SYNC_SCHEDULING_V1.7.md).

Timestamped historical key-trust records have an implemented bounded profile:
authenticated store capture, complete issuer-chain/policy/checkpoint binding,
independently pinned RFC 3161 receipt verification, and decision replay across
the signed TSA accuracy interval. Current authorization remains a separate
mandatory gate for case use. Acceptance uses a synthetic TSA; global historical
policy completeness and actual prior verifier execution are not proven. See
[Historical key-trust records](docs/reference/CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md).

## Future work

- complete historical policy/revocation and custody evidence beyond the bounded retained-record profile;
- operated policy delivery services, additional deployment identity profiles beyond mTLS, and durable/HA coordination beyond the controlled local scheduling profile;
- independently operated timestamp service deployment, archival TSA revocation evidence, and long-term timestamp renewal;
- additional deterministic parsers and raw-evidence reassessment adapters beyond recorded gate and native CloudTrail replay, plus authorized live comparison orchestration;

- additional provider-specific raw-export parsers beyond the native CloudTrail profile as vendors expose telemetry;
- larger PostgreSQL/HA performance qualification across representative enterprise workloads;
- HSM-specific signing profiles and hardware-backed collector keys;
- private transparency-log implementations and multi-party evidence anchoring;
- more automatic evidence-source coverage measurement and provider schema-change detection;
- additional independent visible-rendering adapters for representation attacks;
- optional standards-based case exchange profiles beyond the current neutral/STIX/ECS exports;
- broader fuzzing and hostile-file corpora for parsers and archive/document intake;
- external independent penetration-test reports and deployment certifications when a production environment exists.

Roadmap items are not treated as implemented evidence capabilities until code, Evidence Packs, analyst documentation, and acceptance tests are present.
