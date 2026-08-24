# Human-in-the-Loop Investigation Guide

AI-DFIR is designed to help an analyst reason from evidence; it must not replace
investigator judgment.

## Decisions that should remain human-controlled

- whether a source is legally/organizationally authorized for acquisition;
- whether destructive or disruptive containment is justified;
- whether two events are causally connected when no explicit lineage exists;
- whether a provider or tool identity is sufficiently attributable;
- whether ambiguous content is malicious rather than merely unusual;
- whether an incident is ready for closure;
- whether evidence may be exported or legal hold released.

## Human review prompts

At each material finding ask:

1. **What is the exact proposition?**
2. **Which artifacts support it?**
3. **What is the evidence quality?**
4. **Does the evidence cover the incident time?**
5. **Is there independent corroboration?**
6. **Could the same observation have a benign explanation?**
7. **What would falsify the conclusion?**
8. **What evidence is missing?**
9. **What downstream consequence still exists?**
10. **What decision requires a human approval?**

## Do not confuse confidence with proof

Model/classifier confidence is not forensic confidence. A 0.99 semantic score
cannot replace a missing provider audit record, target-system log, or chain of
custody.

## Decision record

Use `ANALYST_DECISION_RECORD_TEMPLATE.md` for high-impact decisions.
