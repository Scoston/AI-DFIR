# v0.9 Agentic Incident Evidence Matrix

| Risk | Minimum analyst evidence | Stronger impact evidence |
|---|---|---|
| ASI01 Goal Hijack | Full conversation/system instructions, exact retrieved context, agent config, tool/delegation trace, effective authority | Target-system audit, consequences, causal links from injected content |
| ASI02 Tool Misuse | Tool/MCP catalog and schema, exact tool calls/results, authority/approval policy | Independent target API/system audit and downstream effects |
| ASI03 Identity & Privilege Abuse | Sign-in/workload identity, token issuance/use, roles/scopes/delegations, agent trace | Target audit proving privileged action |
| ASI04 Agentic Supply Chain | Component/ML-BOM, hashes/provenance, MCP/plugin inventory, install/deployment history | Execution trace tying suspect component to incident |
| ASI05 Unexpected Code Execution | Process tree/command line, agent/tool trace, tool schema, filesystem events | Network/C2, container/Kubernetes audit, persistence evidence |
| ASI06 Memory & Context Poisoning | Memory writes/reads/updates, memory snapshot, writer/source provenance, before/after sessions | Explicit memory-read → tool/consequence causal path |
| ASI07 Insecure Inter-Agent Communication | A2A/message-bus logs, agent identities, delegation records, orchestrator trace | Recipient actions and target-system audit |
| ASI08 Cascading Failures | Multi-agent causal trace, dependency topology, queue/retry/task logs, consequence ledger | Containment timing showing propagation before/after controls |
| ASI09 Human-Agent Trust Exploitation | Exact agent output, human approval/decision record, policy | UI rendering/citations/warnings plus executed downstream action |
| ASI10 Rogue Agents | Agent plan/state, stop/cancel records, full tool/delegation trace, authority, persistence/memory | Endpoint/network evidence and unresolved consequences |

## Analyst rule

For every row distinguish:

1. artifact/component existed,
2. artifact/component changed,
3. artifact/component was used,
4. an action occurred,
5. that action caused the consequence.

A conclusion at step 5 requires stronger evidence than step 1.
