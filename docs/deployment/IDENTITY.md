# Enterprise Identity Deployment

## Analyst/API identity

Use direct OIDC verification when possible. Configure a pinned issuer, audience,
JWKS/trust source, tenant claim mapping, and role policy.

For SAML environments, terminate SAML at an enterprise access gateway and issue
AI-DFIR a **signed normalized identity envelope** per request. Do not trust raw
`X-User`, `X-Roles`, or tenant headers.

## Collector identity

Collectors should use mTLS/SPIFFE identities tied to the collector registry.
Preserve the SPIFFE ID, certificate serial, trust domain, incident-time validity,
revocation evidence, collector public-key fingerprint, capabilities, and tenant.

An enrolled collector name by itself is not identity evidence.
