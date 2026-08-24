# Universal Evidence Architecture

v0.8 distinguishes three forensic modes:

| Mode | Example | Expected evidence |
|---|---|---|
| White-box | Qwen/Llama/Gemma/Mistral local checkpoints | weights, tensor deltas, activations, runtime, behavior |
| Gray-box | Claude Code, Agent 365, managed private agent | local/provider config, sessions, tools, identity, retrieval, runtime |
| Black-box | hosted model API | request IDs, model/deployment metadata, prompt/response, tool trace, provider audit, identity |

The same case can contain multiple providers/modes. For example a local Claude Code agent can call a hosted Claude model, read a poisoned web page, invoke an MCP server, and modify Git. Each evidence domain is modeled independently.

## Universal case domains

- model/provider
- prompt/session
- agent/orchestrator
- RAG/retrieval/data
- memory
- MCP/tools
- identity/effective authority
- endpoint/runtime
- cloud/control plane
- network
- downstream target systems
- containment/recovery
