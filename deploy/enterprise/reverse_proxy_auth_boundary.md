# Reverse Proxy / Identity Boundary

The v1.0 API and portal do not implement an IdP.

Production topology:

1. User authenticates to enterprise IdP using the organization's normal OIDC/SAML/MFA flow.
2. An identity-aware reverse proxy validates the IdP session.
3. The proxy maps approved directory groups to an AI-DFIR role.
4. The proxy creates short-lived claims: `sub`, `role`, `tenant_id`, `groups`, `exp`.
5. The proxy HMAC-signs the claims and forwards:
   - `X-AI-DFIR-Auth`
   - `X-AI-DFIR-Auth-Sig`
6. AI-DFIR verifies the HMAC and expiry on every request.

Do not expose ports 8890/8891 directly to untrusted networks.
Do not accept unsigned user-supplied identity headers.
