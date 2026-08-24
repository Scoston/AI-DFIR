# AI-DFIR v1.4 — Runtime Trust Fabric & Stateful Agent Forensics

## Core question

v1.4 moves the platform from artifact-centric AI forensics toward **time-aware execution trust**.

```text
WORKLOAD ATTESTATION / SPIFFE
            |
            v
   WORKLOAD IDENTITY AT T
            |
            v
   CREDENTIAL LINEAGE AT T
            |
            v
    TEMPORAL AUTHORITY AT T
            |
      +-----+------+----------------+
      |            |                |
      v            v                v
   MEMORY       SKILLS          MCP / A2A
   STATE        SUPPLY CHAIN     PROTOCOL
      |            |                |
      +------------+----------------+
                   |
                   v
            MODEL / AGENT
                   |
          OTEL / PROVIDER TRACE
                   |
                   v
          TYPED CAUSAL GRAPH
                   |
                   v
           ACTION / CONSEQUENCE
                   |
                   v
      COLLECTOR COVERAGE + CUSTODY
                   |
                   v
     REVIEW / TRANSPARENCY / EXPORT
```

## Five incident-time propositions

1. **Who was really executing?** — `workload_identity.py`
2. **Which credential chain backed the execution?** — `credential_lineage.py`
3. **What authority existed at that instant?** — `temporal_authority.py`
4. **What persistent state influenced the execution?** — `memory_integrity_v2.py`
5. **Which evidence proves input → decision → action → consequence?** — `causal_graph_v2.py`

## Trust is historical

Current state is not substituted for incident state. Keys, SVIDs, tokens, grants, memory, skills and approvals are evaluated relative to event timestamps whenever evidence permits.

## Missing telemetry is evidence about uncertainty

`collector_health.py` distinguishes unavailable, disabled, incomplete and degraded evidence sources from a clean finding.

## Safe behavioral analysis

`behavioral_sandbox.py` does not execute untrusted artifacts. It defines the isolation contract and analyzes telemetry from an external disposable canary environment.
