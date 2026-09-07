# AI-DFIR v1.7.0 - Investigation Integrity & Offline Verification

**AI-DFIR** is a defensive AI incident-response and digital-forensics platform for investigating models, agents, runtimes, identity, memory, skills, MCP/A2A, representation attacks, provider telemetry, evidence custody, and production assurance.

> **Release status:** v1.7.0 extends the v1.5 signed case-export architecture with investigation-ledger integrity, signed checkpoints, explicit signer-trust semantics, and offline verification. Stable promotion follows successful v1.7.0-rc2 validation of **111/111 Evidence Packs**, all **56 v1.7 regression tests**, committed-source packaging, known-answer verification, and independent verification of the final published GitHub release surface. A GitHub release passing these controls does not by itself certify a specific enterprise deployment as production-ready.

## Why AI-DFIR

The unreleased [Azure Activity Log replay](docs/reference/AZURE_ACTIVITY_REPLAY_V1.7.md)
profile imports native REST responses and EventData arrays for offline signed-case
comparison. It preserves fractional timestamps and separates translated labels,
caller/identity claims, and status observations. Management-plane activity does
not establish model invocation, human attribution, or complete collection.

The unreleased [Google Cloud Audit replay](docs/reference/GCP_AUDIT_REPLAY_V1.7.md)
profile imports native audit exports, preserves nanosecond timestamps, delegation
order and individual permission checks, and compares recorded projections offline.
It keeps caller identity, delegated authority, and operational outcomes distinct.

The unreleased [native CloudTrail replay](docs/reference/CLOUDTRAIL_REPLAY_V1.7.md)
profile imports preserved log files and LookupEvents JSON, retains recorded
identity and event order, and compares projections offline within signed cases.
It rejects malformed inputs and reports collection/authenticity limits separately.

The current development branch also supports validated investigation provenance
and offline recorded replay. This extension is **not included in the published
v1.7.0 assets**. See [Investigation replay](docs/reference/INVESTIGATION_REPLAY_V1.7.md)
for evidence-reference validation, AI/tool/analyst reconstruction, supported pure
transforms, and the synthetic acceptance case.

The unreleased [Evidence Pack gate replay](docs/reference/EVIDENCE_PACK_REPLAY_V1.7.md)
profile checks whether exact retained pack rules and recorded quality ratings
reproduce an assessment's conclusion gates. It detects incorrectly recorded gate
results without acquiring evidence again. A matching calculation does not
validate the original quality ratings or authorize an investigative conclusion.

The unreleased [checkpoint key policy](docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md)
adds verifier-controlled key rotation, retirement, revocation, validity windows,
and tenant/case scope. It reports cryptographic validity separately from current
key trust and can require an independently supplied, pinned policy snapshot.

The unreleased [checkpoint timestamp profile](docs/reference/CHECKPOINT_TIMESTAMPS_V1.7.md)
prepares RFC 3161 requests and authenticates external receipts offline with an
approved CA bundle and a pinned TSA signing certificate. Receipt failure blocks
required verification and reconstruction. Operators supply their timestamp
service and trust material; the tools do not submit evidence or requests.

The unreleased [authenticated policy updates](docs/reference/CHECKPOINT_POLICY_UPDATES_V1.7.md)
profile verifies a separate policy issuer's signature and retains the latest
accepted revision in a verifier-owned transactional store. It rejects older or
conflicting updates and reauthenticates the stored policy on every use. Operators
protect issuer trust and the store; backup recovery can require an independent
minimum revision.

The unreleased [policy issuer quorum](docs/reference/CHECKPOINT_POLICY_QUORUM_V1.7.md)
profile can require multiple approved issuer keys before a policy update is
accepted. Custodians can co-sign on separate systems; every signature binds the
policy and the verifier-approved issuer list and threshold. Distinct keys do
not by themselves prove distinct human custodians.

The unreleased [signed issuer governance](docs/reference/CHECKPOINT_POLICY_GOVERNANCE_V1.7.md)
profile requires both current and replacement issuer quorums to approve root
rotation. It activates the new root and policy in one transaction, retains the
signed chain, and verifies it against an independent starting anchor on each
use. Existing quorum stores can migrate without resetting their policy revision.

The unreleased [online policy delivery](docs/reference/CHECKPOINT_POLICY_DELIVERY_V1.7.md)
profile adds explicit HTTPS synchronization from an operator-configured endpoint.
It checks the complete signed chain against the existing anchor and atomically
activates the final root and policy, including catch-up across missed rotations.
Downloads cannot introduce trust anchors, and case verification stays offline.
The [client certificate authentication profile](docs/reference/POLICY_DELIVERY_MTLS_V1.7.md)
adds explicit, protected TLS client credentials for endpoints that restrict
delivery to approved verifier systems. Transport authentication does not replace
the independent issuer signatures or policy rollback controls.

The unreleased [policy synchronization scheduler](docs/reference/POLICY_SYNC_SCHEDULING_V1.7.md)
adds operator-approved jobs with separate pinned anchors, offline preflight,
explicit single-pass or recurring execution, and bounded retry backoff. Each
store retains its own authenticated policy history; scheduling never starts as
a side effect of case verification.

The unreleased [historical key-trust records](docs/reference/CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md)
profile timestamps a retained signed policy, issuer chain, checkpoint, and trust
decision together. Offline verification reproduces that decision throughout the
TSA accuracy interval. Current authenticated policy remains required for case
use, so a historical approval cannot override a later retirement or revocation.

AI incidents cross boundaries that conventional DFIR tools often treat separately. AI-DFIR is designed to answer:

1. **What actually executed?** Model, agent, harness, tool implementation, workload, and provider.
2. **What state influenced it?** Prompt, retrieval, memory, cache, skill, workspace instructions, and model/runtime state.
3. **Who had authority at the incident time?** Human, workload, credential, delegation, approval, and tenant context.
4. **What did the machine perceive versus the human?** Includes EvilFont-style glyph remapping, hidden document layers, Unicode, markup, and rendered-output attacks.
5. **What action occurred and what consequence escaped the AI boundary?**
6. **What trustworthy evidence proves each link?**
7. **What evidence is missing, unavailable, stale, conflicting, or untrusted?**

## Major forensic layers

```text
Model integrity / tensor geometry
Activation & behavioral attestation
Runtime provenance & fleet attestation
Evidence preservation / containment / recovery
Universal Evidence Layer & provider adapters
Agentic IR / MCP / A2A / browser & computer use
Representation integrity / EvilFont / Unicode / hidden markup
Workload identity / credential lineage / temporal authority
Memory integrity / skill supply chain / caches / routing
OpenTelemetry GenAI / typed causal graph
Distributed enterprise collection / WORM / KMS / legal hold
Production platform assurance / provider certification / DR / SLOs
Human-in-the-loop review / evidence quality / closure gates
```

## Quick start

Python **3.11+** is required.

```bash
./install.sh default
source .venv/bin/activate

python tests/generate_test_corpus.py
python tests/test_evidence_pack_matrix.py
python tests/run_synthetic_scenarios.py
python scripts/release_check.py --quick
```

Windows PowerShell:

```powershell
.\install.ps1 -Profile default
```

Install profiles:

| Profile | Purpose |
|---|---|
| `default` | Core evidence, agent, runtime, representation, and analyst workflows |
| `model` | Adds PyTorch/Transformers model-integrity dependencies |
| `enterprise` | Adds PostgreSQL and supported cloud/KMS/provider SDKs |
| `dev` | Adds test/lint/release tooling |
| `pdf-agpl` | Optional PyMuPDF profile; **read `LICENSE_GUIDE.md` first** |

See [INSTALL.md](INSTALL.md) for installation details.

## Demo

![AI-DFIR v1.6 synthetic demo](docs/demo/DEMO_THUMBNAIL.png)

A reproducible demo uses only synthetic evidence and never requires production credentials:

```bash
python tests/generate_test_corpus.py
python tests/run_synthetic_scenarios.py
python v16_selftest.py --out /tmp/ai-dfir-v16-demo
```

Then launch the read-only Workbench against a prepared case:

```bash
python analyst_dashboard.py --case-root ./cases --host 127.0.0.1 --port 8877
```

Demo assets are under [`docs/demo/`](docs/demo/). Direct video: [`AI-DFIR-v1.6.0-demo.mp4`](docs/demo/AI-DFIR-v1.6.0-demo.mp4).

## Testing

AI-DFIR ships deterministic synthetic validation for the complete current evidence catalog:

```bash
python tests/generate_test_corpus.py
python tests/test_evidence_pack_matrix.py
```

Expected current release result:

```text
111 / 111 Evidence Packs PASS
```

Higher-fidelity synthetic detector scenarios:

```bash
python tests/run_synthetic_scenarios.py
```

Expected current release result:

```text
19 / 19 detector domains PASS
```

Run the release gates:

```bash
python scripts/release_check.py --quick
python scripts/release_check.py --full
```

See [TESTING.md](TESTING.md) and [docs/reference/TEST_SCENARIO_CATALOG.md](docs/reference/TEST_SCENARIO_CATALOG.md).

## Analyst workflow and human oversight

Start with:

- [Analyst Quick Start](docs/analyst/ANALYST_QUICKSTART.md)
- [Incident Workflow](docs/analyst/INCIDENT_WORKFLOW.md)
- [Evidence Quality](docs/analyst/EVIDENCE_QUALITY.md)
- [Human in the Loop](docs/analyst/HUMAN_IN_THE_LOOP.md)
- [Production Human in the Loop](docs/analyst/HUMAN_IN_THE_LOOP_PRODUCTION.md)
- [Causality and Attribution](docs/analyst/CAUSALITY_AND_ATTRIBUTION.md)
- [Closure Criteria](docs/analyst/CLOSURE_CRITERIA.md)

The Workbench is intentionally evidence-oriented and read-only for source evidence. It should support analyst judgment, not replace attribution, containment authority, legal-hold release, or case-closure decisions.

## Deployment

Start with [docs/deployment/README.md](docs/deployment/README.md) and [PRODUCTION_READINESS_V1.6.md](PRODUCTION_READINESS_V1.6.md).

Production deployments should use, at minimum:

- HA PostgreSQL with tested tenant isolation/RLS;
- immutable/WORM evidence storage;
- KMS/HSM-backed envelope encryption;
- OIDC/MFA human identity and cryptographic workload identity such as SPIFFE/mTLS;
- separate lab, staging, and production trust domains;
- validated provider collectors and explicit collection-health evidence;
- tested backup/restore, failover, legal hold, upgrade, and rollback;
- signed release provenance, SBOM, checksums, and admission controls;
- independent security assessment and documented human-review gates.

A GitHub release passing CI is **not** equivalent to a deployment being production-ready.

## Documentation map

Use [docs/README.md](docs/README.md) as the documentation index. Key release documents include:

- [V1.6_RUNBOOK.md](V1.6_RUNBOOK.md)
- [PRODUCTION_READINESS_V1.6.md](PRODUCTION_READINESS_V1.6.md)
- [PLATFORM_ASSURANCE_V1.6.md](PLATFORM_ASSURANCE_V1.6.md)
- [PRODUCTION_ASSURANCE_IMPLEMENTATION_MATRIX_V1.6.md](PRODUCTION_ASSURANCE_IMPLEMENTATION_MATRIX_V1.6.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [DATA_HANDLING.md](DATA_HANDLING.md)
- [SECURITY.md](SECURITY.md)

## GitHub publication

The repository includes issue/PR templates, Dependabot, CI, CodeQL, dependency review, OpenSSF Scorecard, release/provenance, container-signing, and documentation checks under `.github/`.

Before publishing, follow [UPLOAD_CHECKLIST.md](UPLOAD_CHECKLIST.md). Repository ownership is defined in [`.github/CODEOWNERS`](.github/CODEOWNERS), including security-sensitive repository paths.

## Licensing

AI-DFIR is licensed under **Apache License 2.0**. Review:

- [LICENSE](LICENSE)
- [NOTICE](NOTICE)
- [LICENSE_GUIDE.md](LICENSE_GUIDE.md)
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

**PyMuPDF is not installed by default** because its AGPL/commercial licensing differs from the AI-DFIR project license. The optional PDF profile is deliberately separated.

## Security reporting

Do **not** open a public issue containing exploit details, credentials, private keys, customer evidence, or sensitive provider data. Follow [SECURITY.md](SECURITY.md) and use GitHub Private Vulnerability Reporting when enabled.

## Project status

AI-DFIR is a defensive/reference implementation with production-assurance controls. Its test results establish the behavior of the released software and synthetic fixtures; they do not certify an organization's IdP, cloud permissions, provider retention, database cluster, KMS/HSM, or evidence-storage deployment.
