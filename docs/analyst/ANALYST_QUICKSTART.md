# Analyst Quickstart

## The first rule

**Preserve before interpreting.** Do not normalize, render, replay, or sanitize
the only copy of evidence.

## First 15 minutes

1. create a case;
2. record incident window, tenant, systems, suspected models/agents/providers;
3. preserve raw provider/local evidence and acquisition metadata;
4. identify whether containment can destroy volatile state;
5. select an Evidence Pack from the alert/incident type;
6. document sources that are unavailable or outside retention;
7. start the read-only Workbench only after source evidence is preserved.

```bash
python case_init.py --case-id IR-001 --root ./cases
python evidence_pack_engine.py catalog
python evidence_pack_engine.py resolve --alert-title "<alert title>"
```

## Never infer clean from absence

These are different:

```text
no malicious event found
source unavailable
source not authorized
source retention expired
collector failed
source not applicable
```

Only the first is a negative observation, and even that is bounded by collection
coverage.

## Evidence proposition ladder

Keep these separate:

```text
artifact existed
artifact changed
artifact was used
an action occurred
an action caused a consequence
an actor/tool can be attributed
```

A strong report says which rung the evidence actually supports.
