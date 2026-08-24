# AI-DFIR v1.6 Production Readiness

v1.6 changes the meaning of **production ready** from a configuration claim to a
set of current, reproducible control evidence.

## Required production evidence

A production deployment should produce current evidence for:

1. PostgreSQL HA, schema level, RLS and FORCE RLS.
2. Immutable/WORM evidence storage and legal-hold enforcement.
3. KMS/HSM key state, key separation and rotation.
4. Enterprise human identity through pinned OIDC or a signed identity gateway.
5. Workload identity through SPIFFE/mTLS or an equivalent attested identity.
6. Provider collector completeness and current provider certifications.
7. Clock synchronization and uncertainty.
8. Backup/restore and controlled failover drills.
9. External transparency/provenance evidence.
10. Release checksum/SBOM/provenance verification.
11. Tenant-isolation tests.
12. Default-deny network segmentation.
13. Container/image admission requiring digest, signature and provenance.
14. Signed analyst audit and independent peer review.
15. Independent security assessment covering trust boundaries.
16. Production PostgreSQL load/SLO evidence.
17. Upgrade and rollback rehearsal.
18. Separate lab, staging and production trust domains/resources.

## Final gate

```bash
python production_readiness_v16.py \
  --config config/production_readiness_v16.example.json \
  --out production_readiness_v16.json
```

A result is intentionally time-sensitive. A deployment can move from READY to
NOT READY when a provider certification expires, a restore drill becomes stale,
a collector misses its SLO, or a signing key is revoked.

## Production threshold

Do not mark production ready until the organization has actually executed:

- database primary loss;
- collector worker loss;
- provider API outage;
- temporary object-store failure;
- KMS outage;
- IdP outage;
- clock-skew test;
- backup restore;
- legal hold/release;
- key rotation;
- failed upgrade + rollback;
- tenant-isolation negative tests;
- unsigned/mutable image admission negative tests.

The supplied `chaos_validation_v16.py` evaluates drill results. It does not
trigger destructive production failures.
