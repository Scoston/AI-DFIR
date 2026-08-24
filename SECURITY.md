# Security Policy

## Supported version

Security fixes are applied to the latest release branch. Older research releases
remain available for reproducibility but should not be treated as supported
production software.

| Version | Supported |
|---|---|
| 1.6.x | Yes |
| <= 1.5 | Reference/research only |

## Reporting a vulnerability

Do **not** open a public issue containing exploit details, credentials, customer
evidence, or sensitive provider data.

Preferred process:

1. Use GitHub **Private vulnerability reporting / Security Advisory** for the
   repository when enabled.
2. If private reporting is not enabled, open a minimal public issue requesting a
   private security contact **without disclosing the vulnerability details**.
3. Include the affected version, component, impact, reproduction prerequisites,
   and whether evidence confidentiality or integrity may be affected.

Maintainers should acknowledge reports, establish a private remediation channel,
and publish a coordinated advisory after a fix is available.

## Security-sensitive areas

Changes to the following require independent review and negative tests:

- evidence hashing/signing/encryption;
- acquisition and provider collectors;
- identity, A2A, MCP, OAuth/OIDC/SPIFFE verification;
- tenant/RLS authorization;
- legal hold and retention;
- containment/recovery;
- evidence-quality and closure logic;
- parsers for untrusted documents/logs;
- GitHub Actions and release automation.

## Threat model

See `THREAT_MODEL.md` and `docs/reference/SECURITY_MODEL.md`.
