# v1.2 Changelog — Representation Integrity & Adversarial Content

## Core forensic change

Added first-class distinction between:

```text
source bytes
machine-readable representation
human-visible representation
```

## EvilFont / font deception

Added:

- tool-independent glyph-outline collapse detection
- blank-glyph mass mapping
- layout-table state
- DOCX OOXML embedded-font analysis
- OOXML font deobfuscation for inspection
- per-character Word font switching
- EvilFont-style hex/suffix-0 supporting IOCs
- EvilFont-style HTML per-character font analysis
- local CSS/font-face analysis
- PDF invisible-text mode and image/text-layer signals
- human-vs-machine representation differential
- dedicated detection guide and Evidence Pack

## Representation attacks

Added:

- Unicode tag/bidi/zero-width/variation/confusable analysis
- hidden Markdown/HTML source analysis
- terminal ANSI/OSC analysis
- representation parity comparison
- deterministic content intake quarantine

## Agent/coding environment

Added:

- approval-content TOCTOU analysis
- signed session-history checkpoints
- AI IDE/LSP/MCP/tool/skill/hook inventory
- DNS/rendering exfiltration analysis
- static archive/extension intake
- adversarial path-name indicators

## Evidence integrity

Hardened:

- mandatory artifact hash binding by default
- exact/unique acquisition-manifest matching
- signed acquisition manifest
- verified `ACQUISITION_TRUST.json`
- authoritative/correlated promotion only after cryptographic trust verification

## Semantic analysis boundary

Added `semantic_verdict_ingest.py`.

It never calls an LLM and accepts only bounded hash-bound classifier verdict
metadata.

## Evidence Packs

Added 10 v1.2 packs.

Total Evidence Packs: **64**.

## Known remaining gaps

- full RFC 8785 + JWS Agent Card verification against enterprise trust stores
- fleet-scale LSH/MinHash prompt-replication indexing
- typed taint edges beyond generic parent/cause
- provider-native representation collectors
- production KMS KEK/DEK envelope encryption
- HA/object-lock enterprise deployment.
