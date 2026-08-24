# Security Model Reference

AI-DFIR treats evidence inputs, provider responses, documents, model artifacts,
agent memory, tool schemas, and collector hosts as potentially hostile.

The platform therefore favors:

- offline/static parsing where possible;
- no arbitrary remote shell in collectors;
- offline-first A2A/JWKS trust;
- content hashing before normalization;
- separate raw and derivative evidence;
- role-separated signing keys;
- incident-time identity/credential evaluation;
- read-only analyst interface;
- explicit missing/unavailable evidence states;
- immutable encrypted custody in production.

See root `THREAT_MODEL.md` for adversaries and protected assets.
