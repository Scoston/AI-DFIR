# v1.3 Changelog — A2A Identity, Signed Agent Cards & Delegation Trust

## New standards-conformant A2A trust layer

Added:

- strict Agent Card JSON parsing
- duplicate-key rejection
- I-JSON validation
- A2A v1.0 field-presence/default handling
- RFC 8785 JCS canonicalization
- RFC 7515 JWS verification
- Agent Card `signatures` exclusion
- ES256
- RS256
- PS256
- EdDSA/Ed25519

## Trust-store hardening

Added signed offline trust stores containing:

```text
kid
JWK
RFC 7638-style JWK thumbprint
trusted key source URL
provider organization
provider URL
allowed agent origins
not-before
expiry
revocation
assurance label
```

Remote `jku` fetching is disabled by design.

## JWS hardening

Added:

- algorithm allowlist
- `typ=JOSE` policy
- protected `kid` / `alg`
- unprotected-header collision rejection
- unprotected `jku` rejection
- unsupported `crit` rejection
- `b64=false` rejection
- JWK `alg`, `use`, `key_ops` checks
- multiple same-`kid` candidate evaluation
- multi-signature trust policy

## Agent Card history

Added:

- same-version content mutation
- skill expansion/removal
- interface changes
- security-scheme changes
- capability changes
- key rotation
- full key replacement

## Execution/delegation binding

Added:

- execution-to-card SHA binding
- declared-skill enforcement
- tenant binding
- task/context consistency
- principal drift
- authority escalation detection

## Evidence Packs

Added:

```text
a2a.signed_agent_card_trust
a2a.signing_key_lifecycle
a2a.execution_identity_binding
a2a.push_callback_identity
```

Total packs: **68**.

## Enterprise workflow

A2A trust findings are now shown in:

```text
case model
Analyst Workbench
investigator report
closure readiness
```

A failed Agent Card trust policy or unresolved critical execution-binding
finding can block case closure.
