# Model Integrity Investigation

Use the model-integrity layers when the incident may involve modified weights,
adapters, runtime hooks, behavioral tampering, quantization changes, or model
replacement.

Evidence stack:

```text
provenance
+ static tensor geometry
+ activation geometry
+ behavioral fingerprints
+ live runtime evidence
+ deployment timeline
```

A clean disk hash does not rule out runtime-only intervention. Conversely, a
behavioral change alone does not prove weight tampering.

Compare like-for-like model revisions, quantization, tokenizer, chat template,
framework version, generation parameters, and system instructions.
