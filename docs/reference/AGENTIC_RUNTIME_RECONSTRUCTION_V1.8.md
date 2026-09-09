# AI-DFIR v1.8 — Agentic Forensics & Runtime Reconstruction

Status: **development profile; not a published stable release**

## Purpose

v1.8 introduces a common forensic representation for observable autonomous execution. The goal is to reconstruct, from retained evidence, the path from a trigger or human request through agent context, retrieval/memory, delegated identity, policy/approval, tool/protocol activity, and externally observable side effects.

The profile does **not** claim to recover private model chain-of-thought or prove subjective intent. It records observable inputs, outputs, state transitions, policy/authority context, protocol exchanges, and evidence bindings.

## Core primitive: Agent Execution Record (AER)

`v18_agent_execution_record.py` defines `ai-dfir/agent-execution-record/v1.8`.

AER nodes represent observable entities/events such as:

- human or machine triggers;
- agents, models, workflows, context and retrieval;
- memory reads/writes;
- policy, approvals and delegated identity;
- tools, protocols and inter-agent communication;
- actions, resources and side effects.

Edges bind those nodes using constrained relationships such as `instructed`, `retrieved`, `wrote_memory`, `delegated_authority`, `selected_tool`, `invoked`, `acted_on`, and `changed`.

Each edge can separately retain:

- evidence references and chunk IDs;
- authority context;
- policy context;
- approval context;
- confidence (`observed`, `corroborated`, `inferred`, `unknown`);
- fields that remain unknown.

The record itself is deterministically serialized and SHA-256 bound. This is an integrity binding, not a source-authenticity claim.

## MCP recorder/replayer

`v18_mcp_forensics.py` targets the MCP `2026-07-28` protocol profile while retaining the actually observed version.

The recorder preserves:

- exact request and response bytes;
- SHA-256 and byte length for each message;
- normalized HTTP headers;
- JSON-RPC method/name;
- observed MCP protocol version;
- task-extension indicator;
- header/body method or tool-name divergence.

The replay function is intentionally inert. It returns retained JSON for offline analysis and sets both `network_performed` and `tool_executed` to false. It does not connect to an MCP server and does not repeat an incident action.

MCP protocol changes are expected over time. Raw exchange retention and explicit protocol-version binding are therefore required even when a normalized field is available.

## RAG and memory provenance

`v18_rag_memory.py` preserves retrieval and memory evidence without pretending the capture is exhaustive.

Retrieval records bind:

- exact query bytes;
- index identifier and revision;
- embedding model name/version supplied by the evidence source;
- optional reranker identity;
- candidate and returned document IDs;
- chunk IDs, ranks and scores;
- exact retained chunk bytes when available.

Memory records bind:

- operation (`read`, `write`, `delete`, `expire`);
- memory/namespace identity;
- source execution ID;
- before, input and after byte identities;
- observed time and optional TTL.

This enables investigators to distinguish a later memory state from the evidence that caused or recorded a mutation. `causal_effect_proven` remains false unless separately established.

## OpenTelemetry GenAI adapter

`v18_otel_genai.py` accepts dictionary or OTLP-style attribute arrays and produces a non-destructive evidence wrapper.

The adapter normalizes selected `gen_ai.*` fields including agent, conversation, workflow, operation, provider, model, system instructions, input/output messages, retrieval query/documents and tool fields. It also preserves the complete original span as canonical bytes with SHA-256 and size.

The semantic-convention version is supplied explicitly by the operator/exporter and retained in the record. The adapter treats the GenAI semantic-convention surface as evolving and does not silently reinterpret unmapped attributes.

Because prompt, completion, retrieval and system-instruction fields may contain sensitive data, deployment-specific collection, minimization and retention controls remain operator responsibilities.

## Agentic detection mappings

`v18_agentic_detections.py` maps explicit observed signals to the OWASP Top 10 for Agentic Applications 2026 and relevant MITRE ATLAS technique names.

The mapping includes ASI01 through ASI10:

1. Agent Goal Hijack
2. Tool Misuse & Exploitation
3. Identity & Privilege Abuse
4. Agentic Supply Chain Vulnerabilities
5. Unexpected Code Execution (RCE)
6. Memory & Context Poisoning
7. Insecure Inter-Agent Communication
8. Cascading Failures
9. Human-Agent Trust Exploitation
10. Rogue Agents

Detections are evidence gates, not attack verdicts. A finding is emitted only when an explicit boolean observation is present in a retained AER node. Absence of a finding does not prove safety, and a framework mapping does not prove attacker intent.

## AI/ML-BOM

`v18_ai_ml_bom.py` inventories AI runtime materials including:

- models and embedding models;
- tokenizers and adapters;
- runtimes, containers and libraries;
- tools, skills, connectors and MCP servers;
- datasets and retrieval stores;
- policy components.

Dependencies form an explicit directed graph. The module can create a conservative CycloneDX 1.7-shaped projection with model components represented as `machine-learning-model` where applicable.

The internal record deliberately leaves `inventory_complete`, `component_authenticity_verified`, and `cyclonedx_conformance_verified` false. Schema conformance must be established by an actual CycloneDX validator before it is claimed.

## Evidence and claim boundaries

The v1.8 development profile must preserve these boundaries:

- **No private chain-of-thought claim.** AI-DFIR records observable context and execution evidence, not hidden reasoning.
- **No active MCP replay.** Forensic replay is offline and must not re-run tools.
- **No source-authenticity inference from hashing.** A hash proves identity relative to retained bytes, not who created them.
- **No completeness inference.** Missing telemetry, RAG chunks, memory history, protocol exchanges or side effects remain explicit unknowns.
- **No framework-verdict inflation.** OWASP/ATLAS mappings are investigative pivots and review signals.
- **No standards-conformance claim without validation.** Version-shaped adapters are not certification.

## Initial acceptance evidence

Repository-controlled acceptance consists of:

- Python compilation under the repository quick gate;
- `v18_agentic_selftest.py` covering all six v1.8 capability families;
- `tests/test_v18_agentic_runtime.py` validating hash/edge binding, replay inertness, RAG/memory custody, OTel raw preservation, explicit-signal detection gating and AI/ML-BOM projection;
- a dedicated GitHub Actions workflow that runs the self-test and regressions on every pull request and `main` push.

This is synthetic/offline acceptance. It does not qualify a production agent platform, external MCP implementation, telemetry collector, vector database, memory service or CycloneDX validator.

## External references/version anchors

- Model Context Protocol specification profile: `2026-07-28` — https://modelcontextprotocol.io/
- OpenTelemetry GenAI semantic conventions — https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
- OWASP Top 10 for Agentic Applications 2026 — https://genai.owasp.org/
- MITRE ATLAS — https://atlas.mitre.org/
- CycloneDX 1.7 / AI-ML BOM — https://cyclonedx.org/

## Next qualification work

The first v1.8 milestone intentionally establishes the common evidence model before provider-specific capture expansion. Follow-on work should add:

- native capture adapters for selected agent frameworks and model providers;
- versioned A2A/inter-agent message capture;
- browser/computer-use side-effect evidence;
- differential execution comparison across model/prompt/policy versions;
- temporal reconstruction and clock-uncertainty fields across distributed agents;
- privacy-preserving/redacted evidence views cryptographically linked to retained originals;
- larger hostile corpora for protocol, memory, retrieval and agent-graph reconstruction;
- live interoperability qualification only against named, authorized targets.
