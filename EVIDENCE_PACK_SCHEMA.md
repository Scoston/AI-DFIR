# AI-DFIR v0.8 Evidence Pack Schema

Each pack is a JSON document with `schema: ai-dfir/evidence-pack/v0.8`.

Required concepts:

- `id`, `title`, `vendor`, `platform`, `incident_type`
- `forensic_modes`: white-box, gray-box, and/or black-box
- `match`: alert IDs/titles, platform, agent or detection families
- `artifacts`: mandatory/conditional/optional evidence requirements
- `presence_patterns`: case-relative patterns used only for local sufficiency triage
- `locations`: likely native locations; these are guidance, not proof of acquisition
- `questions`: investigator questions the pack is intended to answer
- `conclusion_gates`: evidence dependencies for defensible conclusions
- `sources`: vendor documentation used to define the pack

## Hard rule

Unsupported or unavailable evidence is `MISSING/UNKNOWN`, never `CLEAN`.

## Artifact priorities

- **mandatory** — required for the pack's core forensic conclusion
- **conditional** — required when its condition applies
- **optional** — enrichment only

## Conclusion gates

A gate is supported only when its required artifact IDs are present. The engine does not infer a factual conclusion merely because the artifacts exist; it only states that the evidence prerequisites for that conclusion are available.
