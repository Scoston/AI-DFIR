# Provider Capability Matrix

| Provider/source | Current native path | Typical evidence | Important limitation |
|---|---|---|---|
| Microsoft Graph Security | `microsoft_graph_security` | alerts/incidents where authorized | API coverage depends on tenant licensing/retention |
| Azure AI/Foundry diagnostics | `azure_foundry_logs` | resource/diagnostic logs | must be enabled before incident |
| OpenAI organization telemetry | `openai_org` | organization usage/audit surfaces exposed by API | not a substitute for application-side request logging |
| Anthropic | `anthropic_compliance`, `anthropic_usage` | compliance/usage exports exposed to account | availability depends on account/plan and retention |
| AWS Bedrock/CloudTrail | `aws_bedrock` | CloudTrail/Bedrock activity | data events/logging configuration matters |
| Google Cloud | `google_cloud_logs` | Cloud Logging/Audit Logs | sink/retention and filter coverage matter |
| GitHub Copilot | `github_copilot` | enterprise audit records | IDE-local context still needs endpoint/workspace evidence |
| Claude Code | local collector | history/session/workspace controls | local files may be altered; preserve acquisition metadata |
| Cursor | local collector | workspace/session/app evidence | provider-side telemetry may be unavailable |

For every provider, use collection-health and Evidence Pack logic to distinguish
"no record" from "source could not answer".
