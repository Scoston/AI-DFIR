# v1.6 Production Assurance Implementation Matrix

| Recommendation | v1.6 implementation | Validation |
|---|---|---|
| Real HA database / failover | external PostgreSQL requirement, RLS/FORCE RLS, migrations, v1.5 live HA probe retained | v1.6 readiness + controlled chaos result |
| Physical evidence immutability | v1.5 Object Lock/WORM + legal hold retained | Platform Assurance + storage probe |
| Real human/workload identity | v1.5 OIDC/SAML signed gateway + SPIFFE/mTLS retained | Platform Assurance and readiness evidence |
| KMS/HSM | v1.5 KMS envelope adapters retained | KMS probe + rotation evidence |
| Collector certification | `provider_certification_v16.py` with expiring test receipts | seven required certification tests |
| Distributed worker reliability | v1.5 signed enrolled workers + v1.6 chaos/SLO gates | collector-loss / queue/SLO drills |
| Network segmentation | Helm default-deny network policy, hardening validator | `network_policy_validation_v16.py` |
| Application hardening | non-root/read-only/cap-drop/seccomp production chart | static validation + independent security assessment |
| Software supply chain | GitHub SLSA v2.1.0 provenance, SBOM, checksums, Cosign container signing | `release_integrity_v16.py` + admission policy |
| Continuous monitoring | `platform_assurance_v16.py` Workbench panel | fresh control evidence required |
| Scale | v1.5 PostgreSQL benchmark retained | v1.6 readiness requires production benchmark |
| DR | v1.5 signed restore verification + v1.6 chaos drills | current restore + failover evidence |
| Data governance | v1.5 legal hold, redaction, tenant metadata retained | readiness + HITL controls |
| Human oversight | production HITL gate matrix and existing peer review | documented approval gates |
| Independent security validation | `security_assurance_v16.py` | current independent report, full required scope, zero critical/high unresolved by default |
| Upgrade safety | checksum-protected migrations + `upgrade_assurance_v16.py` | backup/migration/post-check/rollback drill |
| Environment separation | distinct lab/staging/prod trust resources | `environment_separation_v16.py` |
| Admission control | OPA-style digest/signature/SLSA policy | negative admission tests supplied by deployment |
| GitHub production surface | CODEOWNERS, CI, full regression, CodeQL, dependency review, Scorecard, SLSA release, signed container, Dependabot | `github_repo_check_v16.py` |

No row means the project has magically deployed or independently certified an organization's infrastructure. v1.6 supplies the implementation and evidence gates; the organization must generate deployment-specific proof.
