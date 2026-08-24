# AI-DFIR v1.6 Demo Script

**Target runtime:** ~95 seconds.

## 0–8s — What AI-DFIR is

AI-DFIR is an AI-specific incident-response and digital-forensics platform. It investigates not only what a model said, but what model and agent actually executed, what state influenced the decision, what authority existed at the time, and what evidence proves the path to consequence.

## 8–20s — Reproducible installation and tests

Show the default install followed by synthetic test-corpus generation. Emphasize that no customer data or production credentials are needed.

## 20–32s — Evidence quality

Run the Evidence Pack matrix. Explain that file presence is not enough: evidence must be hash-bound and meet the required quality threshold. Current release target: 111/111 packs pass.

## 32–44s — Representation integrity

Show EvilFont-style and Unicode/hidden-source findings. Explain that AI-DFIR separately preserves source bytes, machine-readable representation, and human-visible representation.

## 44–58s — Runtime trust

Show A2A identity, workload identity, credential lineage, temporal authority, memory, skills, MCP, and causal graph results. Stress that signature validity is not the same as trust, and correlation is not the same as causation.

## 58–74s — Analyst Workbench

Open the read-only Workbench. Show case findings, evidence quality, A2A/runtime trust, representation integrity, and Platform Assurance.

## 74–86s — Human in the loop

Highlight human gates for attribution, destructive containment, legal-hold release, evidence sharing, and closure. The tool organizes and tests evidence; the investigator remains accountable for judgment.

## 86–96s — Production readiness

Show the distinction between a production-capable software release and a production-ready deployment. HA, WORM, KMS/HSM, identity, provider certification, DR, independent testing, and SLO evidence must pass in the actual environment.
