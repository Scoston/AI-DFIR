# Provider Capability Matrix

| Provider/source | Current native path | Typical evidence | Important limitation |
|---|---|---|---|
| Microsoft Graph Security | `microsoft_graph_security` | alerts/incidents where authorized | API coverage depends on tenant licensing/retention |
| Azure AI/Foundry diagnostics | `azure_foundry_logs` | resource/diagnostic logs | must be enabled before incident |
| Automatic Log Analytics context capture (development) | [`azure_foundry_logs --capture-context`](LOG_ANALYTICS_CAPTURE_V1.7.md) | Prepared request observations, exact bounded entity-body bytes, compatible context/projection artifacts, and completion receipt | explicit workspace POST acquisition only; incomplete/unknown collection and unverified effective scope remain separate from capture completion |
| Preserved Log Analytics results (development) | [`log_analytics_v17.py`](LOG_ANALYTICS_REPLAY_V1.7.md) | Typed table/column/row projection and offline signed-case replay with partial-error preservation | response rows may be aggregates or transformed data; no query execution, verified scope, or complete-collection inference |
| Retained Log Analytics request context (development) | [`log_analytics_context_v17.py`](LOG_ANALYTICS_CONTEXT_V1.7.md) | Separate signed request-context artifact bound to exact response digest/size and typed result projection | explicit workspace POST or bounded GET profile; context is a retained assertion, not proof of actual execution, effective scope, or completeness |
| Retained Log Analytics GET URL (development) | [`log_analytics_context_v17.py --format workspace-get`](LOG_ANALYTICS_GET_CONTEXT_V1.7.md) | Exact workspace URL plus decoded query/timespan binding, strict percent decoding, and offline signed-case comparison | query/optional timespan only; no ambiguous form encoding, extra GET parameters, resource paths, or GET acquisition |
| Preserved Azure Activity Log JSON (development) | [`azure_activity_v17.py`](AZURE_ACTIVITY_REPLAY_V1.7.md) | Native REST/array management-plane metadata projection and offline signed-case replay | not Log Analytics tables; recorded activity/claims do not establish model invocation, human attribution, downstream effects, or complete collection |
| OpenAI organization telemetry | `openai_org` | organization usage/audit surfaces exposed by API | not a substitute for application-side request logging |
| Anthropic | `anthropic_compliance`, `anthropic_usage` | compliance/usage exports exposed to account | availability depends on account/plan and retention |
| AWS Bedrock/CloudTrail | `aws_bedrock` | CloudTrail/Bedrock activity | data events/logging configuration matters |
| Preserved native CloudTrail JSON (development) | [`cloudtrail_v17.py`](CLOUDTRAIL_REPLAY_V1.7.md) | Records/LookupEvents metadata projection and offline signed-case replay | parser does not acquire evidence, prove collection completeness, or authenticate AWS origin |
| Google Cloud | `google_cloud_logs` | Cloud Logging/Audit Logs | sink/retention and filter coverage matter |
| Preserved Google Cloud Audit JSON (development) | [`gcp_audit_v17.py`](GCP_AUDIT_REPLAY_V1.7.md) | Native audit metadata, delegation/permission projection, and signed-case replay | recorded identity and permission checks do not establish human attribution, successful effects, or complete collection |
| GitHub Copilot | `github_copilot` | enterprise audit records | IDE-local context still needs endpoint/workspace evidence |
| Claude Code | local collector | history/session/workspace controls | local files may be altered; preserve acquisition metadata |
| Cursor | local collector | workspace/session/app evidence | provider-side telemetry may be unavailable |

For every provider, use collection-health and Evidence Pack logic to distinguish
"no record" from "source could not answer".
The Azure Log Analytics collector now retains incomplete/unknown completeness
metadata after HTTP success; its existing Boolean receipt flag is false for both
states. See the query-result profile for interpretation.
