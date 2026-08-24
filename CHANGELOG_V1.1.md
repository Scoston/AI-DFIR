# v1.1 Changelog — Execution Integrity & Advanced Agent Attack Surfaces

## Forensic correctness

- Evidence Pack requirements no longer treat filename/glob presence as sufficient.
- New evidence quality states:
  - MISSING
  - PRESENT_UNVALIDATED
  - VALIDATED
  - CORRELATED
  - AUTHORITATIVE
  - CONFLICTING
  - STALE
  - INCOMPLETE
- Conclusion gates support minimum evidence quality.
- Acquisition manifests bind hashes, source attribution, time coverage and clock quality.
- Present-but-unvalidated artifacts become `VALIDATION_REQUIRED` evidence tasks.
- Closure blocks on mandatory evidence below quality and conflicting evidence.

## New forensic surfaces

- Agent Harness Forensics
- Source-to-Sink AI Taint Tracking
- Browser / Computer-Use Forensics
- Agent Session / Context Hijacking
- Outstanding Delegated Work
- A2A v1.0 Forensics
- Model Router / Gateway Forensics
- AI Cache Forensics
- Coding-Agent Workspace Trust
- AI Output Rendering / Active Content Forensics
- Effective Tool Identity / Namespace Shadowing
- Advanced MCP execution-integrity analysis
- Prompt Self-Replication detection
- Agent Birth/Death Certificates
- Cross-Tenant Context Bleed packs

## Repository / timeline hardening

- New streamed `AIDFIR2` chunked AES-256-GCM format.
- Backward-compatible AIDFIR1 extraction.
- Strongest-classification tracking for deduplicated objects.
- Signed repository Merkle anchors for external trust-domain storage.
- Clock offset/uncertainty intervals and ambiguous ordering in forensic timelines.

## Evidence Pack catalog

- 54 total packs.
- 17 new v1.1 advanced execution-integrity packs.
- All Microsoft, Claude, OWASP Agentic and generic v0.8/v0.9 packs retained.

## Compatibility

- v1.0 enterprise suite retained.
- v0.9 agentic suite retained.
- v0.7 workbench suite retained.
- v0.6 containment/recovery suite retained.
