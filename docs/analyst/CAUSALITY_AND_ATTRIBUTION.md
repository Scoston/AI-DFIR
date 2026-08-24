# Causality and Attribution

Use typed relationships rather than timestamp proximity:

```text
caused_by
derived_from
contains_content_from
authorized_by
delegated_by
scheduled_by
retrieved_from
transformed_from
routed_by
executed_by
correlated_with
contradicts
```

`correlated_with` must never be presented as `caused_by` without additional
evidence.

For any material causal claim, the analyst should be able to answer:

> Which evidence IDs support every edge from the source to the consequence?

Attribution should distinguish artifact/tool attribution, signing-key identity,
workload/session identity, human principal identity, and organizational
responsibility.
