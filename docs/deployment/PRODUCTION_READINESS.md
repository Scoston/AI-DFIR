# Production Readiness Gate — v1.6

```bash
python production_readiness_v16.py \
  --config /etc/ai-dfir/readiness-v16.json \
  --out production_readiness_v16.json
```

Optionally provide the lower-level/base readiness result when your deployment process separates base infrastructure validation from v1.6 production-assurance evidence:

```bash
python production_readiness_v16.py \
  --config /etc/ai-dfir/readiness-v16.json \
  --base-result /var/lib/ai-dfir/production_readiness_v15.json \
  --out production_readiness_v16.json
```

v1.6 evaluates current evidence for PostgreSQL/HA and RLS, immutable storage, KMS/HSM, pinned analyst and workload identity, provider certification, collector/service health, DR/failover exercises, environment separation, release integrity/provenance, independent security assessment, upgrade/rollback, network policy, SLOs, production-scale benchmarking, signed analyst audit, peer review, redaction validation, legal hold, and related enterprise controls.

The gate is intentionally fail-closed: configuration claims without supporting probe/validation evidence should not pass. A passing software release is not evidence that a particular deployment is production-ready.
