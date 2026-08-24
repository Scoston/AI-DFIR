# Human-in-the-Loop Production Operations

Automation may collect, hash, normalize, compare, detect and prioritize.
Production authority remains explicitly human-controlled for high-impact steps.

## Mandatory human gates

| Gate | Minimum reviewer |
|---|---|
| Enable new production provider collector | Platform owner + evidence custodian |
| Change retention / WORM policy | Evidence custodian + legal/security |
| Change production trust roots / IdP / SPIFFE trust domain | Identity owner + security approver |
| Change KMS key or rotation policy | Key custodian + platform owner |
| Release legal hold | Evidence custodian + authorized legal approver |
| Destructive containment | Incident commander + service owner unless emergency policy says otherwise |
| Attribute malicious intent | Investigator + independent reviewer |
| Assert causal consequence | Investigator; peer review for critical cases |
| Close case with evidence gaps | Incident commander + independent reviewer |
| Promote release to production | Release approver after provenance/readiness gates |

## Live analyst questions

Before relying on an automated finding, ask:

1. What evidence supports it?
2. Is that evidence hash-bound and attributable?
3. Was the evidence source healthy during the incident window?
4. Is the conclusion causal, derived, authorized, delegated, or merely correlated?
5. Did a human and the AI perceive equivalent content?
6. Was the workload identity and credential trusted **at that time**?
7. Did the agent possess the authority it used at that time?
8. Is a provider retention/logging gap hiding part of the timeline?
9. Has another investigator reproduced the critical conclusion?
10. Which statement would change if one evidence source were later invalidated?

## Stop conditions

Escalate instead of auto-closing when:

- Platform Assurance is CRITICAL.
- mandatory provider collection is incomplete;
- evidence quality is below the pack gate;
- causal edge evidence is missing;
- legal hold is active;
- unresolved downstream consequences remain;
- critical identity/authority/A2A findings remain;
- peer review is incomplete.
