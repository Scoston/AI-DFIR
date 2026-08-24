# AI-DFIR v1.1 — Execution Integrity Architecture

v1.1 adds a new forensic layer between the AI application and the existing
model/agent evidence stack:

```text
UNTRUSTED INPUT
     |
     v
SOURCE-TO-SINK TAINT
     |
     v
AGENT HARNESS
     |
 +---+----------+-----------+-----------+
 |              |           |           |
 v              v           v           v
MODEL          RAG        MEMORY       CACHE
 |              |           |           |
 +--------------+-----------+-----------+
                |
                v
        EFFECTIVE AUTHORITY
                |
      +---------+----------+-------------+
      |                    |             |
      v                    v             v
     MCP                  A2A        BROWSER / GUI
      |                    |             |
      +---------+----------+-------------+
                |
                v
           TOOL IDENTITY
                |
                v
        DOWNSTREAM ACTION
                |
                v
           CONSEQUENCE
                |
                v
    OUTSTANDING DELEGATED WORK
                |
                v
           CONTAINMENT
```

## New v1.1 principle

A matching artifact filename is not sufficient forensic evidence.

Every evidence requirement can now distinguish:

```text
MISSING
PRESENT_UNVALIDATED
VALIDATED
CORRELATED
AUTHORITATIVE

CONFLICTING
STALE
INCOMPLETE
```

Conclusion gates use evidence quality, not only presence.

## Advanced attack-surface domains

v1.1 adds first-class analysis for:

- agent harness drift / compromise
- source-to-sink AI taint propagation
- browser / computer-use agents
- session/context hijacking
- outstanding async/delegated work
- A2A v1.0 Agent Cards/tasks/contexts/push callbacks
- model router/provider fallback drift
- prompt/context/RAG/tool/MCP cache poisoning
- workspace control/instruction poisoning
- active output rendering
- effective tool identity / namespace shadowing
- MCP authorization, tasks, root boundaries and catalog caches
- prompt self-replication / AI-worm propagation candidates
- agent lifecycle certificates
- cross-tenant context bleed
- acquisition clock uncertainty

## Forensic proposition ladder

The platform continues to distinguish:

1. a component **existed**,
2. it **changed**,
3. it was **used**,
4. an **action occurred**,
5. the action **caused a consequence**.

v1.1 adds a sixth dimension:

6. the evidence supporting those propositions is **good enough to rely on**.
