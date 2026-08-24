# Synthetic and Normalized Log Formats

Synthetic logs under `tests/fixtures/` are deliberately fabricated and safe for
training/testing. They use JSON/JSONL shapes similar to the platform's normalized
event and provider envelopes but must not be mistaken for vendor-certified raw
schemas.

Categories:

- provider raw/receipt fixtures;
- OTel GenAI spans;
- agentic event JSONL;
- A2A/MCP task events;
- browser/network/cache/router events;
- identity/credential/authority events;
- memory/skill/workspace events;
- enterprise custody/collection health.

Each fixture directory contains `README.md` or manifest metadata explaining what
the scenario is expected to demonstrate.
