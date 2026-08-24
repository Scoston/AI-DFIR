# Controlled Failover / Chaos Drills

Run drills in staging first. Production drills require change approval and incident readiness. Required scenarios are database primary loss, collector loss, provider outage, object-store transient failure, KMS outage, identity-provider outage and clock skew. Record start/end, expected behavior, recovery seconds, duplicated/lost evidence count and investigator impact. Feed the JSON results to `chaos_validation_v16.py`.
