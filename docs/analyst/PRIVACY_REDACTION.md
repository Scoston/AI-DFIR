# Privacy and Redaction

Preserve original evidence under appropriate access controls. Produce separate
redacted derivatives for sharing.

Use deterministic redaction plus a manifest and validate that:

- source SHA-256 matches the manifest;
- redacted SHA-256 matches the manifest;
- requested redaction classes were applied;
- the redacted file is a derivative, not a replacement for the original.

Do not paste unredacted prompts, credentials, user data, or incident exports into
public issue trackers or external AI systems without authorization.
