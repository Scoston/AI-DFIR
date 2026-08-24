# Case Evidence Directory Layout

`case_init.py` creates versioned evidence directories. Important logical groups
include:

```text
00_case                  case metadata
model/static             checkpoint and tensor evidence
activation/runtime       fingerprints and live evidence
agentic                   sessions, tools, retrieval, memory
containment               plans, preservation, consequences
representation            documents/fonts/visible-machine comparisons
A2A/MCP                   protocol identity and task evidence
runtime trust             credentials, authority, skills, OTel, causal graph
enterprise                provider collection, identity, storage, SLO, DR
reports                    deterministic investigator outputs
```

The exact directory names remain in `case_init.py`; analysts should reference
files by evidence ID/hash in conclusions rather than relying only on folder
location.
