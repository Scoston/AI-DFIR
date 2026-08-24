# v0.6 Changelog — Automated Containment & Forensic Preservation

Added:
- signed containment control with atomic writes
- application-level ContainmentGuard
- modes: observe, freeze-tools, read-only, quarantine, failover, released
- signed containment plans
- independent plan approval binding
- preservation-first transaction executor
- signed pre/post containment evidence seals
- explicit evidence-preservation failure policy
- hash-chained containment audit
- fleet alert auto-responder (dry-run / approval / auto)
- approved failover health precheck
- optional Linux process-memory acquisition
- downstream consequence reconciliation
- signed release request and approval
- release blocking for failed checks/open consequences
- fail-closed enforcement on tampered containment controls
- auto-responder systemd template
- v0.6 synthetic acceptance suite

Retained:
- v0.5 continuous fleet attestation
- v0.4 execution provenance/replay
- v0.3 live activation attestation
- v0.2 activation fingerprinting
- v0.1 static model-integrity forensics
