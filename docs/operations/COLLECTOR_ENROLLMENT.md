# Collector Enrollment & Rotation

## Objective
Bind every distributed acquisition worker to an enrolled collector identity rather than a caller-supplied name.

1. Create the collector workload identity (prefer SPIFFE/mTLS).
2. Register collector ID, certificate/SPIFFE fingerprint and allowlisted collector types.
3. Verify the collector can lease only its tenant's signed tasks.
4. Run a synthetic acquisition and verify the signed receipt.
5. Disable the collector before rotating identity.
6. Register the new fingerprint/SVID and re-enable after verification.

Never place general shell commands in distributed acquisition tasks. Only named allowlisted collectors may execute.
