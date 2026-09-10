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

Status: **single-span adapter and bounded multi-span reconstruction are merged; bounded OTLP JSON trace/log envelope intake is implemented on the current development branch and requires PR qualification; live collector/exporter interoperability remains open**

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
- [x] OTLP 1.11.0 JSON trace-envelope intake (`resourceSpans/scopeSpans/spans`)
- [x] OTLP 1.11.0 JSON log-envelope intake (`resourceLogs/scopeLogs/logRecords`)
- [x] exact source-envelope custody when observed JSON bytes are supplied
- [x] resource/instrumentation-scope context retention
- [x] replay validation binding derived span/log entries back to the retained source envelope
- [x] strict trace/span ID and duplicate-attribute validation
- [x] selected imported trace -> AER reconstruction wrapper with source-envelope binding
- [x] trace/log identifier correlation with explicit non-causality claims
- [x] dedicated bounded-population synthetic qualification profile (2,048 spans / 4,096 logs / 8 traces)
- [ ] OTLP binary Protobuf/gRPC intake and transport custody
- [ ] OTLP File Exporter multi-envelope JSONL intake
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

Status: **inventory, deterministic validation, expected-vs-observed drift, and the pinned external CycloneDX 1.7 synthetic projection qualification are merged to `main`; exact operator/production exports still require their own validation evidence**

- [x] inventory for models, tokenizers, adapters, runtimes, tools, MCP servers, connectors, datasets, retrieval stores, policies, skills, containers and libraries
- [x] deterministic component/dependency ordering and internal record validation
- [x] dependency graph
- [x] CycloneDX 1.7 projection
- [x] default non-conformance claim retained for arbitrary/unvalidated exports
- [x] compare two bound incident-time/expected BOM snapshots
- [x] missing, unexpected and modified component drift findings
- [x] dependency, component-property and source-version drift findings
- [x] report binding to both source BOM hashes
- [x] no-drift-is-safety and drift-is-compromise claims explicitly remain false
- [x] checksum-pinned CycloneDX `sbom-utility` v0.19.2 validation against the built-in 1.7 schema
- [x] positive projection plus known-invalid negative-control validation
- [x] network-isolated validation phase and retained qualification receipt/artifact
- [ ] validate each production/operator-exported BOM when conformance is asserted for that exact artifact

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
