# v0.5 Changelog — Continuous Fleet Attestation

Added:

- per-node Ed25519 identities
- signed chained heartbeats
- anti-replay and out-of-order rejection
- optional TLS and mTLS
- signed collector receipts
- central SQLite evidence/alert store
- fleet state machine with recovery hysteresis
- stale and never-seen node detection
- fast metadata-tree integrity measurement
- slow/cached full model content-tree SHA-256
- approved model/fingerprint/runtime/template/tokenizer policy
- unapproved adapter detection
- unapproved hook fingerprint detection
- activation-divergence policy
- delegated-authority policy drift
- tool-schema drift
- retrieval-config drift
- hardware-attestation policy
- Prometheus metrics
- OpenTelemetry-style fleet metric export
- scheduled controlled activation canary runner
- node disable/revocation
- key rotation
- signed incident snapshot helper
- hardened systemd templates
- v0.5 end-to-end synthetic fleet acceptance test

Retained:

- all v0.4 static, replay, provenance, OCSF, runtime, activation, timeline and evidence-correlation tooling.
