# Credential and Delegated-Authority Lineage — v1.8

## Purpose

AI-DFIR v1.8 can reconstruct observable credential and delegated-authority lineage around agent actions without retaining reusable bearer credentials. The profile is intended to help an investigator answer questions such as:

- Which credential observation was associated with an agent or workload action?
- Was a new credential observed as the result of a token exchange, assume-role, impersonation, delegated session, or on-behalf-of event?
- Which principal was observed on each side of that exchange?
- Did the observable audience, issuer, principal, or scope set change?
- Was one credential fingerprint observed with more than one presenter?
- Is part of the credential or principal parentage missing from the retained evidence?
- Which authority edges are supported by explicit delegation evidence, and which observations are only correlations?

The module does **not** attempt to infer private model reasoning or human intent.

## Evidence objects

The profile uses six bounded records:

1. `ai-dfir/credential-observation/v1.8`
2. `ai-dfir/jwt-structure/v1.8`
3. `ai-dfir/principal-observation/v1.8`
4. `ai-dfir/credential-delegation-hop/v1.8`
5. `ai-dfir/credential-presentation/v1.8`
6. `ai-dfir/credential-lineage/v1.8`

A lineage can then be projected into `ai-dfir/credential-lineage-aer/v1.8` for integration with the Agent Execution Record.

## Credential handling boundary

Reusable credential bytes supplied to `credential_observation()` are used only to calculate a SHA-256 correlation fingerprint and byte length. The raw value is not placed in the returned evidence record.

SHA-256 is **not encryption**. A fingerprint must not be treated as a safe password verifier or proof of authenticity, particularly for low-entropy secrets. Credential metadata rejects obvious nested secret-shaped fields such as access tokens, refresh tokens, client secrets, passwords, API keys, and raw credential values.

Source systems and evidence stores remain responsible for appropriate access control, retention, encryption, and legal handling of any separately retained original evidence.

## JWT observation boundary

`jwt_structure()` supports a bounded three-part compact JWT structural profile. It records selected observable fields useful for investigation pivots, including:

- `alg`, `kid`, `typ`, and `cty` header fields;
- `iss`, `sub`, `aud`, `client_id`, `scope`/`scp`, `exp`, `nbf`, `iat`, and `jti` claims;
- the RFC 8693-style `act` actor identity pivots `sub`, `iss`, and `client_id` when present.

The decoder is deliberately **not a JWT verifier**. Signature validity, issuer trust, audience validation, and time-claim validation remain false in the structural record. A separately validated identity/trust source must be bound before making those claims.

Strict base64url and JSON parsing rejects malformed encodings, duplicate JSON keys, non-finite JSON values, non-string identity pivots, and timezone-naive observation timestamps.

## Delegation versus presentation

A credential presentation says only that retained evidence correlated a principal, credential identifier, target, and time. Even when a downstream authorization result was observed, presentation by itself does not prove how the credential was obtained or that authority was delegated by a particular upstream actor.

For that reason:

- presentation records project to AER as `correlated_with` edges;
- they never become `delegated_authority` solely because a credential was presented;
- `delegated_authority` edges require an explicit `credential-delegation-hop` observation.

Supported hop labels are evidence categories, not protocol-conformance claims:

- OAuth token exchange;
- assume role;
- service-account impersonation;
- workload-identity exchange;
- delegated session;
- on-behalf-of;
- other explicitly observed exchange mechanisms.

## Diagnostics

The lineage builder reports:

- missing credential IDs;
- missing principal IDs;
- credential-fingerprint reuse across distinct observed presenters;
- scope additions/removals across a hop;
- audience changes;
- principal changes;
- issuer changes;
- structural JWT expiration and not-before observations.

A structural expiration/not-before observation does not mean the JWT signature or issuer was valid. The diagnostic only compares retained numeric claims to the normalized observation time.

Cyclic credential delegation graphs fail closed. Duplicate credential, principal, hop, presentation, and JWT-to-credential identities also fail closed rather than allowing ambiguous graph reconstruction.

## AER projection

Principals and credentials use separate AER identity namespaces so an identical external identifier cannot collapse a principal and credential into one node. Missing parents become explicit `unknown` nodes.

Each explicit delegation hop produces evidence-bound authority/correlation edges with authority, policy, approval, confidence, and unknown-field context preserved. Presentation edges remain correlations.

The AER projection continues to assert false for:

- complete credential lineage;
- credential authenticity;
- principal control;
- human intent;
- private reasoning capture.

## Qualification

`.github/workflows/credential-lineage-v18-qualification.yml` runs deterministic regression coverage and a bounded synthetic population. The qualification retains a receipt and summaries as GitHub Actions artifacts.

The synthetic profile exercises chained credential exchanges, multiple principals, JWT actor pivots, scope/audience changes, credential reuse, AER projection, and raw-secret non-retention.

Passing this gate establishes only the repository-controlled synthetic profile. It does **not** establish:

- live OAuth/OIDC provider interoperability;
- JWT signature or issuer validation;
- completeness of a production credential lineage;
- production authorization correctness;
- control of an identity by the observed principal;
- production scale or availability;
- independent security assessment.

Those require separately retained evidence from the actual provider, identity system, agent runtime, policy decision point, and deployment being investigated.
