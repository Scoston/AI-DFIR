# AI-DFIR v1.8 Development Roadmap

## Theme

**Agentic Forensics & Runtime Reconstruction**

The v1.8 line makes observable autonomous execution a first-class forensic object. The organizing primitive is the Agent Execution Record (AER), which links human/event triggers, agent context, retrieval and memory, identity/authority, policy/approval, protocol/tool activity and side effects to retained evidence.

## Milestone 0 — common evidence model

Status: **merged to `main` with repository-controlled synthetic acceptance; production qualification is not claimed**

- [x] Agent Execution Record with bounded node/edge vocabulary
- [x] SHA-256 evidence references with optional chunk IDs
- [x] explicit authority, policy, approval, confidence and unknown-field context on edges
- [x] machine-readable JSON Schema
- [x] hard prohibition on claiming private chain-of-thought capture

## Milestone 1 — MCP recorder and inert replay

Status: **baseline merged; live interoperability remains externally gated**

- [x] exact JSON-RPC request/response byte retention
- [x] observed MCP protocol-version binding
- [x] `Mcp-Method` / JSON-RPC method divergence detection
- [x] `Mcp-Name` / request-name divergence detection
- [x] task-extension indicator
- [x] offline replay that cannot invoke tools or the network
- [ ] named live MCP client/server interoperability qualification
- [ ] OAuth/issuer evidence capture against an authorized implementation

## Milestone 2 — RAG and memory provenance

Status: **baseline merged; broader adapters remain**

- [x] exact query-byte identity
- [x] index ID and revision
- [x] embedding-model metadata
- [x] candidate/returned document identities
- [x] chunk IDs, scores and ranks
- [x] before/input/after memory-state custody for read/write/delete/expire events
- [ ] native vector-store adapters
- [ ] native framework memory adapters
- [ ] retrieval reranker/provider-specific acquisition context

## Milestone 3 — OpenTelemetry GenAI and AER reconstruction

Status: **single-span adapter merged; bounded multi-span reconstruction implemented on the current development branch and subject to PR qualification**

- [x] dictionary and OTLP-style attribute ingestion
- [x] agent/conversation/workflow/model/tool/retrieval field normalization
- [x] complete raw-span preservation
- [x] explicit semantic-convention version binding
- [x] unmapped GenAI attribute inventory
- [x] bounded single-trace multi-span AER graph assembly
- [x] deterministic output independent of source-span input order
- [x] every source span bound into AER raw evidence
- [x] explicit orphan-parent, missing-span-ID and unmapped-span diagnostics
- [x] duplicate span IDs and cyclic parent graphs fail closed
- [x] trace relationships represented as correlation rather than inferred intent/business causality
- [ ] OTLP trace/log envelope import at scale
- [ ] named collector/exporter interoperability qualification

## Milestone 4 — agentic detection mappings

Status: **implemented evidence-gated baseline**

- [x] OWASP ASI01–ASI10 mapping
- [x] MITRE ATLAS technique-name pivots
- [x] explicit observed-signal gating
- [x] no finding-as-proof and no absence-as-safety claims
- [ ] evidence-pack content for each ASI risk
- [ ] provider/framework-specific detections
- [ ] multi-event correlation and temporal/cascade analytics

## Milestone 5 — AI/ML-BOM

Status: **implemented baseline**

- [x] inventory for models, tokenizers, adapters, runtimes, tools, MCP servers, connectors, datasets, retrieval stores, policies, skills, containers and libraries
- [x] dependency graph
- [x] CycloneDX 1.7-shaped projection
- [x] explicit non-conformance claim until validator evidence exists
- [ ] actual CycloneDX 1.7 schema validation in CI
- [ ] import and compare two incident-time BOM snapshots
- [ ] expected-vs-observed component drift findings

## Milestone 6 — reconstruction depth

Status: **planned**

- [ ] A2A/inter-agent protocol capture with named version contracts
- [ ] browser/computer-use evidence: screenshot, DOM/accessibility tree, target, typed content, download/upload and before/after state
- [ ] delegated-token/credential lineage graph
- [ ] differential execution comparison across model, prompt, policy and tool versions
- [ ] temporal reconstruction with event, provider, tool, ingestion and monotonic time plus uncertainty
- [ ] privacy-preserving/redacted evidence views cryptographically bound to retained originals

## Milestone 7 — resilience and qualification

Status: **planned/external where noted**

- [ ] million-event synthetic agent cases
- [ ] large cyclic/branching agent graphs
- [ ] retries, duplicate tool calls, cancellation, partial responses and reordered events
- [ ] crash-during-write and interrupted evidence-pack generation
- [ ] clock skew and cross-provider time disagreement
- [ ] hostile MCP/RAG/memory/OTel corpora and fuzz targets
- [ ] authorized live provider/framework compatibility matrix
- [ ] independent penetration test and external security assessment

## Release gates

No v1.8 capability is promoted solely because source code exists. Promotion requires:

1. committed implementation and operator documentation;
2. deterministic regression coverage;
3. retained acceptance evidence for the exact environment exercised;
4. explicit false/unknown claims for anything not established;
5. no production, interoperability, authenticity or conformance claim without corresponding external evidence.
