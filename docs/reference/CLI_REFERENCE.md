# CLI Reference

Generated from `--help` output for key release entry points.

## `case_init.py`

```text
usage: case_init.py [-h] [--case-id CASE_ID] --root ROOT

options:
  -h, --help         show this help message and exit
  --case-id CASE_ID
  --root ROOT
```

## `analyst_dashboard.py`

```text
usage: analyst_dashboard.py [-h] --case-root CASE_ROOT [--host HOST]
                            [--port PORT]

options:
  -h, --help            show this help message and exit
  --case-root CASE_ROOT
  --host HOST
  --port PORT
```

## `evidence_pack_engine.py`

```text
usage: evidence_pack_engine.py [-h] {catalog,resolve,assess,profile} ...

positional arguments:
  {catalog,resolve,assess,profile}

options:
  -h, --help            show this help message and exit
```

## `enterprise_v15_analyze.py`

```text
usage: enterprise_v15_analyze.py [-h] --case CASE

options:
  -h, --help   show this help message and exit
  --case CASE
```

## `provider_collectors_v15.py`

```text
usage: provider_collectors_v15.py [-h] [--params-json PARAMS_JSON] --out OUT
                                  {anthropic_compliance,anthropic_usage,aws_bedrock,azure_foundry_logs,github_copilot,google_cloud_logs,microsoft_graph_security,openai_org}

positional arguments:
  {anthropic_compliance,anthropic_usage,aws_bedrock,azure_foundry_logs,github_copilot,google_cloud_logs,microsoft_graph_security,openai_org}

options:
  -h, --help            show this help message and exit
  --params-json PARAMS_JSON
  --out OUT
```

## `provider_gap_analysis_v15.py`

```text
usage: provider_gap_analysis_v15.py [-h] --provider PROVIDER
                                    [--available AVAILABLE]
                                    [--unavailable-json UNAVAILABLE_JSON]
                                    [--out OUT]

options:
  -h, --help            show this help message and exit
  --provider PROVIDER
  --available AVAILABLE
  --unavailable-json UNAVAILABLE_JSON
  --out OUT
```

## `enterprise_evidence_ingest_v15.py`

```text
usage: enterprise_evidence_ingest_v15.py [-h] --src SRC --tenant TENANT
                                         --case CASE --dsn DSN
                                         --kek-json KEK_JSON
                                         --store-json STORE_JSON
                                         [--classification CLASSIFICATION]
                                         [--retention-days RETENTION_DAYS]
                                         [--legal-hold]
                                         [--receipt-sha256 RECEIPT_SHA256]
                                         [--media-type MEDIA_TYPE] [--out OUT]

options:
  -h, --help            show this help message and exit
  --src SRC
  --tenant TENANT
  --case CASE
  --dsn DSN
  --kek-json KEK_JSON
  --store-json STORE_JSON
  --classification CLASSIFICATION
  --retention-days RETENTION_DAYS
  --legal-hold
  --receipt-sha256 RECEIPT_SHA256
  --media-type MEDIA_TYPE
  --out OUT
```

## `distributed_acquisition_v15.py`

```text
usage: distributed_acquisition_v15.py [-h] {create,verify,verify-receipt} ...

positional arguments:
  {create,verify,verify-receipt}

options:
  -h, --help            show this help message and exit
```

## `collector_worker_v15.py`

```text
usage: collector_worker_v15.py [-h] --dsn DSN --tenant TENANT
                               --collector-id COLLECTOR_ID
                               [--capability CAPABILITY] --outdir OUTDIR
                               --receipt-dir RECEIPT_DIR
                               --private-key PRIVATE_KEY
                               [--lease-seconds LEASE_SECONDS]
                               [--identity-json IDENTITY_JSON]
                               [--allow-unverified-reference]

options:
  -h, --help            show this help message and exit
  --dsn DSN
  --tenant TENANT
  --collector-id COLLECTOR_ID
  --capability CAPABILITY
  --outdir OUTDIR
  --receipt-dir RECEIPT_DIR
  --private-key PRIVATE_KEY
  --lease-seconds LEASE_SECONDS
  --identity-json IDENTITY_JSON
  --allow-unverified-reference
```

## `oidc_identity_v15.py`

```text
usage: oidc_identity_v15.py [-h] --token TOKEN --jwks JWKS --issuer ISSUER
                            --audience AUDIENCE
                            [--evaluation-time EVALUATION_TIME] [--out OUT]

options:
  -h, --help            show this help message and exit
  --token TOKEN
  --jwks JWKS
  --issuer ISSUER
  --audience AUDIENCE
  --evaluation-time EVALUATION_TIME
  --out OUT
```

## `spiffe_mtls_v15.py`

```text
usage: spiffe_mtls_v15.py [-h] --leaf LEAF --bundle BUNDLE
                          [--trust-domain TRUST_DOMAIN]
                          [--spiffe-id SPIFFE_ID] [--usage {client,server}]
                          [--evaluation-time EVALUATION_TIME] [--crl CRL]
                          [--out OUT]

options:
  -h, --help            show this help message and exit
  --leaf LEAF
  --bundle BUNDLE
  --trust-domain TRUST_DOMAIN
  --spiffe-id SPIFFE_ID
  --usage {client,server}
  --evaluation-time EVALUATION_TIME
  --crl CRL
  --out OUT
```

## `legal_hold_v15.py`

```text
usage: legal_hold_v15.py [-h] {create,release,validate} ...

positional arguments:
  {create,release,validate}

options:
  -h, --help            show this help message and exit
```

## `legal_hold_apply_v15.py`

```text
usage: legal_hold_apply_v15.py [-h] --dsn DSN --hold HOLD
                               --hold-public-key HOLD_PUBLIC_KEY
                               --store-json STORE_JSON [--release RELEASE]
                               [--release-public-key RELEASE_PUBLIC_KEY]
                               [--out OUT]

options:
  -h, --help            show this help message and exit
  --dsn DSN
  --hold HOLD
  --hold-public-key HOLD_PUBLIC_KEY
  --store-json STORE_JSON
  --release RELEASE
  --release-public-key RELEASE_PUBLIC_KEY
  --out OUT
```

## `dr_integrity_v15.py`

```text
usage: dr_integrity_v15.py [-h] {create,validate} ...

positional arguments:
  {create,validate}

options:
  -h, --help         show this help message and exit
```

## `case_export_v15.py`

```text
usage: case_export_v15.py [-h] {create,verify} ...

positional arguments:
  {create,verify}

options:
  -h, --help       show this help message and exit
```

## `production_readiness_v15.py`

```text
usage: production_readiness_v15.py [-h] --config CONFIG [--out OUT]

options:
  -h, --help       show this help message and exit
  --config CONFIG
  --out OUT
```

## `production_readiness_v16.py`

```text
usage: production_readiness_v16.py [-h] --config CONFIG
                                   [--base-result BASE_RESULT] [--out OUT]

options:
  -h, --help            show this help message and exit
  --config CONFIG
  --base-result BASE_RESULT
  --out OUT
```

## `a2a_trust_analyze.py`

```text
usage: a2a_trust_analyze.py [-h] --case CASE --card CARD
                            --trust-store TRUST_STORE
                            [--trust-public-key TRUST_PUBLIC_KEY]
                            [--allow-unsigned-trust-store]
                            [--previous-card PREVIOUS_CARD] [--events EVENTS]

options:
  -h, --help            show this help message and exit
  --case CASE
  --card CARD
  --trust-store TRUST_STORE
  --trust-public-key TRUST_PUBLIC_KEY
  --allow-unsigned-trust-store
  --previous-card PREVIOUS_CARD
  --events EVENTS
```

## `mcp_forensics_v14.py`

```text
usage: mcp_forensics_v14.py [-h] --log LOG
                            [--approved-app-origin APPROVED_APP_ORIGIN]
                            [--approved-extension APPROVED_EXTENSION]
                            [--out OUT]

options:
  -h, --help            show this help message and exit
  --log LOG
  --approved-app-origin APPROVED_APP_ORIGIN
  --approved-extension APPROVED_EXTENSION
  --out OUT
```

## `evil_font_forensics.py`

```text
usage: evil_font_forensics.py [-h] [--out OUT] path

positional arguments:
  path

options:
  -h, --help  show this help message and exit
  --out OUT
```

## `otel_genai_ingest.py`

```text
usage: otel_genai_ingest.py [-h] --input INPUT --out OUT
                            [--events-out EVENTS_OUT] [--include-content]

options:
  -h, --help            show this help message and exit
  --input INPUT
  --out OUT
  --events-out EVENTS_OUT
  --include-content
```

## `closure_gate.py`

```text
usage: closure_gate.py [-h] --workspace WORKSPACE [--repository REPOSITORY]
                       [--repository-key-hex REPOSITORY_KEY_HEX] [--out OUT]

options:
  -h, --help            show this help message and exit
  --workspace WORKSPACE
  --repository REPOSITORY
  --repository-key-hex REPOSITORY_KEY_HEX
  --out OUT
```
