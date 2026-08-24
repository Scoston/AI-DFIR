# AI-DFIR v1.3 — A2A Identity, Signed Agent Cards & Delegation Trust

## Goal

v1.3 closes the A2A trust gap identified in v1.2.

A2A v1.0 allows Agent Cards to be signed using:

```text
RFC 8785 JSON Canonicalization Scheme (JCS)
            +
RFC 7515 JSON Web Signature (JWS)
```

AI-DFIR now independently verifies those signatures and keeps **cryptographic
validity**, **enterprise trust**, **transport identity**, and **delegated
authority** as separate forensic propositions.

## Trust model

```text
RECEIVED AGENT CARD
        |
        v
Strict JSON parse
  - duplicate-key rejection
  - I-JSON validation
        |
        v
A2A v1.0 field-presence/default handling
        |
        v
Exclude signatures[]
        |
        v
RFC 8785 JCS
        |
        v
JWS signing input
 protected + "." + base64url(JCS payload)
        |
        v
Cryptographic verification
        |
        +--> ES256
        +--> RS256
        +--> PS256
        +--> EdDSA/Ed25519
        |
        v
SIGNED TRUST STORE
        |
        +--> kid
        +--> JWK thumbprint
        +--> provider organization
        +--> provider URL
        +--> allowed Agent Card interface origins
        +--> trusted JWKS source URL
        +--> not-before / expiry
        +--> revocation
        +--> assurance label
        |
        v
TRUST POLICY
        |
        v
TRUSTED AGENT CARD
```

## Important distinction

```text
VALID JWS
```

means:

> The card has not changed since a holder of the corresponding private key
> signed its canonical payload.

It does **not** automatically mean:

```text
the provider is trusted
the endpoint is trusted
the key is still approved
the request actually came from that agent
the requested task was authorized
the agent stayed within delegated authority
```

v1.3 models each separately.

## Offline-first key retrieval

The verifier does not fetch `jku` URLs supplied by untrusted cards.

Instead:

```text
incident acquisition / approved registry
       |
       v
captured JWKS
       |
       v
signed AI-DFIR trust store
```

The JWS `jku` may be checked against the trusted source URL stored with the key.

This prevents signature verification from becoming an SSRF or attacker-
controlled trust-bootstrap mechanism.

## Multi-signature/key rotation

A2A Agent Cards may carry multiple signatures.

v1.3 supports:

```text
old key + new key overlap
multiple trusted signers
rotation history
revocation
expiration
same-version card mutation
full signing-key replacement
```

## Execution binding

Agent Card JWS protects the Agent Card, not every A2A request.

v1.3 therefore separately binds execution evidence:

```text
trusted card
    |
    +--> canonical card SHA-256
    +--> declared skills
    +--> declared tenant/interface
    +--> security schemes
    |
    v
observed A2A task/message
    |
    +--> task ID
    +--> context ID
    +--> principal
    +--> agent ID
    +--> card SHA-256
    +--> skill ID
    +--> tenant
    +--> transport/auth evidence
    +--> authority before
    +--> authority after
    |
    v
delegation / identity findings
```

Examples:

```text
a2a_undeclared_skill_invoked
a2a_tenant_binding_mismatch
a2a_execution_card_hash_mismatch
a2a_unapproved_authority_escalation
a2a_task_context_split
a2a_task_principal_drift
```

## Evidence chain

```text
Agent Card bytes
       +
JCS canonical payload
       +
JWS signature
       +
signed trust store
       +
captured JWKS provenance
       +
transport authentication
       +
task/context trace
       +
effective authority
       +
target audit
       =
defensible A2A incident reconstruction
```
