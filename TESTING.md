# Testing AI-DFIR v1.6.0

AI-DFIR ships complementary validation layers. All bundled fixtures are synthetic and must not contain production credentials or customer evidence.

## 1. Current acceptance suite

```bash
python v16_selftest.py --out /tmp/aidfir-v16
```

Historical suites are retained for compatibility regression.

## 2. Evidence Pack fixture matrix

Generate deterministic synthetic case files and acquisition hashes for **every current Evidence Pack**:

```bash
python tests/generate_test_corpus.py
python tests/test_evidence_pack_matrix.py
```

Expected v1.6.0 release result:

```text
111 / 111 PASS
```

The matrix validates evidence discovery, acquisition-hash binding, minimum evidence quality, and mandatory conclusion gates. Generic fixtures do not claim that placeholder content represents a real attack.

## 3. High-fidelity synthetic scenarios

```bash
python tests/run_synthetic_scenarios.py
```

Expected v1.6.0 release result:

```text
19 / 19 detector domains PASS
```

These fabricated scenarios exercise representative detector logic including EvilFont-style representation attacks, Unicode/markup/terminal channels, browser control, DNS exfiltration, cache/router drift, workload identity, credentials, temporal authority, memory, skills, MCP, OpenTelemetry GenAI, typed causality, A2A binding, provider normalization, and collection health.

## 4. GitHub/repository checks

```bash
python scripts/github_repo_check_v16.py
```

This validates the expected GitHub/community surface and detects stale release documentation or unsafe unresolved repository placeholders.

## 5. Release gates

```bash
python scripts/release_check.py --quick
python scripts/release_check.py --full
```

`--full` includes major historical compatibility suites and is the gate used for release packaging.

## 6. Production deployment validation

Software tests do not prove an enterprise deployment is production-ready. After deployment, collect the required HA, identity, WORM, KMS, provider-certification, DR, chaos/failover, SLO, independent-assessment, and upgrade/rollback artifacts and run:

```bash
python production_readiness_v16.py \
  --config config/production_readiness_v16.example.json \
  --out production_readiness_v16.json
```

See `PRODUCTION_READINESS_V1.6.md`.

## 7. Demo and analyst training

See `docs/demo/README.md` and `docs/reference/TEST_SCENARIO_CATALOG.md` for a reproducible synthetic walkthrough.


## 8. v1.7 development: offline verification assurance

The v1.7 development line adds a separate assurance layer for third-party verification of signed case exports. Run:

```bash
python -m pytest tests/test_v17_verification_assurance.py -q
python v17_verification_assurance_selftest.py
```

The assurance self-test invokes `verify_case_v17.py` from a detached working directory with a network guard, validates both text and JSON reports, and checks the verifier exit-code contract: `0` verified, `1` verification failure, `2` malformed/unsupported package, and `3` runtime/configuration error.

See `docs/reference/OFFLINE_VERIFICATION_V1.7.md`.
