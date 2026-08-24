# Event and Causal Evidence Schema

The normalized agentic event model uses explicit event IDs and typed lineage.
Prefer explicit relationships over inference from timestamps.

Common event types include model invocation, retrieval, memory read/write,
tool call/result, delegation, browser action, A2A/MCP task activity, network
action, containment, and consequence.

Typed causal relationships include:

```text
caused_by
derived_from
contains_content_from
authorized_by
delegated_by
scheduled_by
retrieved_from
transformed_from
routed_by
executed_by
correlated_with
contradicts
```

Every normalized event should preserve or reference the raw source artifact and
its hash whenever possible.
