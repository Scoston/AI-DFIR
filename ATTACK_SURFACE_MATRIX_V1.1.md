# AI-DFIR v1.1 Advanced Attack Surface Matrix

| Attack surface | Core question | Primary evidence | Analyzer |
|---|---|---|---|
| Agent harness | Did the runtime scaffold change model context, tools, approval, memory or stop behavior? | harness package/version/hash, middleware, hooks, prompt assembly, policies, lifecycle log | `harness_forensics.py` |
| Source-to-sink taint | Where did untrusted content enter and which sinks inherited it? | normalized agentic events with parent/cause links | `taint_tracker.py` |
| Browser/computer use | Did untrusted web/UI content or a browser-control path cause an action? | browser profile, DOM, CDP/computer events, WebSocket, HAR, approvals | `browser_forensics.py` |
| Agent session | Was a session/context reassigned or accessed by another principal? | session registry, token/auth events, reconnects, authority | `session_task_forensics.py` |
| Async work | What work survived containment? | queues, tasks, schedulers, child agents, cancel/stop records | `session_task_forensics.py` |
| A2A v1.0 | Was an Agent Card, task, context, skill or callback identity compromised? | Agent Card, signatures, task/context IDs, OAuth, push callbacks | `a2a_forensics.py` |
| Model routing | Did the requested model resolve to an unapproved provider/model/region/safety profile? | router policy + per-request resolution log + provider audit | `router_forensics.py` |
| AI caches | Did poisoned/stale/cross-tenant cached state influence execution? | cache keys, namespace, TTL, source hashes, writer/reader identity | `cache_forensics.py` |
| Workspace trust | Did repository-controlled instructions/config/scripts manipulate a coding agent? | CLAUDE.md, AGENTS.md, Copilot/Cursor rules, MCP config, Git/CI/hooks | `workspace_trust.py` |
| Output rendering | Did safe-looking model output become dangerous active content? | raw/sanitized/rendered output, sanitizer policy, DOM/network/session events | `output_render_forensics.py` |
| Tool identity | Which exact tool implementation actually executed? | protocol, server identity, cert, schema hash, version, auth context | `tool_identity.py` |
| MCP authorization | Did issuer/client/token binding fail? | OAuth/CIMD/issuer metadata + MCP gateway logs | `mcp_execution_integrity.py` |
| MCP roots | Did a resource/file operation resolve outside the approved root? | roots, resolved path, symlink/fs metadata | `mcp_execution_integrity.py` |
| MCP Tasks | Did long-running work continue after cancel/containment? | tools/call + task lifecycle + cancel records | `mcp_execution_integrity.py` |
| MCP caches | Was stale/cross-tenant discovery state reused? | tools/prompts/resources catalogs + ttlMs/cacheScope | `mcp_execution_integrity.py` |
| Prompt replication | Did an instruction propagate between agents/sessions? | cross-agent message corpus + causal trace | `prompt_replication.py` |
| Agent lifecycle | Was an agent spawned without approval or left children/effects behind? | signed birth/death certificates + observed-agent inventory | `agent_lifecycle.py` |
| Cross-tenant bleed | Did memory/cache/RAG/session/router state cross tenant boundaries? | tenant-bound request/session/cache/retrieval/identity evidence | Evidence Pack + cache/session analyzers |
| Evidence quality | Is the evidence itself authentic, relevant, complete and attributable? | acquisition manifest + parser/field/time/hash validation | `evidence_quality.py` |
| Clock integrity | Can event ordering actually be established? | clock offset + uncertainty | `timeline_builder.py` |
