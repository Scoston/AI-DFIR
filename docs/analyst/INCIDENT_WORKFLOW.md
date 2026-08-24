# AI Incident Investigation Workflow

## Phase 1 — Scope and preserve

Capture:

- case/tenant and incident window;
- model/provider/deployment identity;
- agent/harness/session/task IDs;
- workload/user identity;
- provider request IDs;
- RAG/memory/tool/MCP/A2A context;
- downstream systems and consequences.

If runtime-only tampering is possible, preserve live execution evidence before
restarting or replacing the process when operationally feasible.

## Phase 2 — Evidence-source health

Before interpreting logs, determine whether each expected source is available
and covers the incident window. Run collector/provider gap analysis where
applicable.

## Phase 3 — Normalize without destroying raw evidence

Raw evidence remains immutable. Normalized events are derivatives with source
hash/lineage.

## Phase 4 — Reconstruct

Build:

```text
input/source
  -> representation actually consumed
  -> retrieval/memory
  -> prompt/harness
  -> model/provider
  -> decision/task
  -> delegated authority
  -> tool/MCP/A2A/browser action
  -> target-system consequence
```

## Phase 5 — Validate competing hypotheses

For every material conclusion, ask what evidence would disprove it. Preserve
contradictory evidence rather than forcing it into the dominant narrative.

## Phase 6 — Contain and reconcile

Containment of the agent/model does not undo tasks, queued work, credentials,
memory writes, callbacks, or target-system changes that already escaped.

## Phase 7 — Peer review and closure

Use independent review for attribution, destructive containment, legal hold
release, and final incident closure when possible.
