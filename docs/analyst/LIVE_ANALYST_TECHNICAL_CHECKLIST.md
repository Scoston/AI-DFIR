# Live Analyst Technical Checklist

Use this page beside the Workbench during an active investigation.

## Before interpretation

- Verify case/tenant/time window.
- Confirm collector and provider coverage.
- Record clock offsets/uncertainty.
- Verify original artifact hashes and acquisition trust.
- Mark missing, stale, incomplete or conflicting evidence explicitly.

## Model/runtime

- Which model/provider/version actually executed?
- Do weights, adapters, template, tokenizer, runtime hooks and router resolution match approved state?
- If hidden states are unavailable, do not infer clean model integrity.

## Representation

- What bytes did the machine parse?
- What did a human actually see?
- Are there glyph, Unicode, hidden-markup, PDF-layer or terminal-rendering divergences?

## Agent state

- Which memory version was read?
- Which skill/tool/MCP server identity executed?
- Was a tool declared, approved and still trusted at incident time?
- Did a task or child agent remain active after containment?

## Identity/authority

- Which workload identity and credential backed the action?
- Was it valid at incident time?
- What scopes/resource/tenant/purpose constraints applied?
- Was authority elevated or delegated? By whom?

## Causality

Do not use time adjacency alone. Prefer explicit edges: `caused_by`, `derived_from`, `authorized_by`, `delegated_by`, `retrieved_from`, `executed_by`. Keep `correlated_with` separate.

## Impact

- What target-system audit independently proves the action?
- What consequences escaped the AI boundary?
- Which consequences remain open?

## Human decision gates

Require a human decision record before disruptive containment, causal attribution with gaps, malicious-intent claims, legal-hold release, external evidence sharing or closure.
