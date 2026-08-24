# Key Rotation Operations

Rotate separately: evidence KMS KEKs, collector signing keys, response/approval keys, analyst-audit keys, A2A trust-store signing keys and service identities. Preserve old public verification material for evidence created before rotation. Record not-before, expiry and revocation times so historical incident-time trust remains evaluable. Test decrypt/verify before retiring a key.
