# Microsoft AI Alert Evidence-Pack Catalog

Verified against Microsoft documentation on 2026-08-23.

| Alert ID | Alert title | Severity | Evidence pack |
|---|---|---|---|
| `AI.AIModelScan_MalwareDetected` | Malicious content detected in uploaded AI model | High | `microsoft.AI.AIModelScan_MalwareDetected` |
| `AI.Azure_ASCIISmuggling` | ASCII Smuggling prompt injection detected | High | `microsoft.AI.Azure_ASCIISmuggling` |
| `AI.Azure_AccessAnomaly` | Access anomaly in AI resource | Medium | `microsoft.AI.Azure_AccessAnomaly` |
| `AI.Azure_AccessFromAnonymizedIP` | Access from a Tor IP | High | `microsoft.AI.Azure_AccessFromAnonymizedIP` |
| `AI.Azure_AccessFromSuspiciousIP` | Access from suspicious IP | High | `microsoft.AI.Azure_AccessFromSuspiciousIP` |
| `AI.Azure_AccessFromSuspiciousUserAgent` | Suspicious user agent detected | Medium | `microsoft.AI.Azure_AccessFromSuspiciousUserAgent` |
| `AI.Azure_AnomalousOperation.InitialAccess` | Suspicious invocation of a high-risk 'Initial Access' operation by a service principal detected (AI resources) | Medium | `microsoft.AI.Azure_AnomalousOperation.InitialAccess` |
| `AI.Azure_AnomalousToolInvocation` | Anomalous tool invocation | Low | `microsoft.AI.Azure_AnomalousToolInvocation` |
| `AI.Azure_CredentialTheftAttempt` | Detected credential theft attempts on an Azure AI model deployment | Medium | `microsoft.AI.Azure_CredentialTheftAttempt` |
| `AI.Azure_DOWDuplicateRequests` | Suspected wallet attack - recurring requests | Medium | `microsoft.AI.Azure_DOWDuplicateRequests` |
| `AI.Azure_DOWVolumeAnomaly` | Suspected wallet attack - volume anomaly | Medium | `microsoft.AI.Azure_DOWVolumeAnomaly` |
| `AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt` | A Jailbreak attempt on an Azure AI model deployment was blocked by Azure AI Content Safety Prompt Shields | Medium | `microsoft.AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt` |
| `AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt` | A Jailbreak attempt on an Azure AI model deployment was detected by Azure AI Content Safety Prompt Shields | Medium | `microsoft.AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt` |
| `AI.Azure_LLMReconnaissance` | LLM Reconnaissance Attempt Detected | Low | `microsoft.AI.Azure_LLMReconnaissance` |
| `AI.Azure_MaliciousUrl.ModelResponse` | Corrupted AI application/model/data directed a phishing attempt at a user | High | `microsoft.AI.Azure_MaliciousUrl.ModelResponse` |
| `AI.Azure_MaliciousUrl.UnknownSource` | Phishing URL shared in an AI application | High | `microsoft.AI.Azure_MaliciousUrl.UnknownSource` |
| `AI.Azure_MaliciousUrl.UserPrompt` | Phishing attempt detected in an AI application | High | `microsoft.AI.Azure_MaliciousUrl.UserPrompt` |
| `(no AI-specific ID published)` | Exposed Kubernetes service detected |  | `microsoft.ExposedKubernetesService.AI` |

## Agent 365 documented detection families

- jailbreak attempts
- indirect prompt injection (XPIA)
- malicious content propagation
- secret and credential leakage
- evasion techniques
- LLM reconnaissance
- suspicious user or IP access

Microsoft publishes these Agent 365 families as near-real-time threat scenarios. v0.8 resolves them through a family evidence pack instead of fabricating stable alert IDs.
