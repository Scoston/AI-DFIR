# Provider-Native Collectors

`provider_collectors_v15.py` implements read-only collection adapters. Use
service principals with the minimum read scopes required for the endpoint.

```bash
python provider_collectors_v15.py <collector>   --params-json collector-params.json   --out raw-provider-collection.json
```

Collectors:

```text
microsoft_graph_security
azure_foundry_logs
openai_org
anthropic_compliance
anthropic_usage
aws_bedrock
google_cloud_logs
github_copilot
```

For each acquisition preserve the provider response, request parameters without
secrets, provider/request IDs, pagination state, collection-completeness flag,
and collection time. Analyze unavailable expected sources with
`provider_gap_analysis_v15.py`.
