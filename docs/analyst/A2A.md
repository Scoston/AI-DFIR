# A2A Investigation Guide

Separate four propositions:

1. Agent Card JWS is cryptographically valid.
2. Signing key was trusted **at incident time** for that provider/interface.
3. The observed request/session was authenticated as that workload/agent.
4. The task stayed within declared skill, tenant, context, and delegated authority.

Collect Agent Card, signed trust store/JWKS provenance, OAuth/mTLS identity,
request/response hashes, A2A task/context/message IDs, card hash, skill ID,
tenant, authority before/after, callback configuration, and target audit.

Do not infer request authenticity from Agent Card signature alone.
