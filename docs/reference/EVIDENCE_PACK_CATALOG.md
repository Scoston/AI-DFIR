# Evidence Pack Catalog

Total packs: **96**

| ID | Vendor | Platform | Incident type | Mandatory | Conditional |
|---|---|---|---|---:|---:|
| `a2a.execution_identity_binding` | Generic | A2A v1.0 | a2a_execution_identity_binding | 5 | 1 |
| `a2a.push_callback_identity` | Generic | A2A v1.0 | a2a_push_callback_identity | 5 | 0 |
| `a2a.signed_agent_card_trust` | Generic | A2A v1.0 | a2a_signed_agent_card_trust | 4 | 2 |
| `a2a.signing_key_lifecycle` | Generic | A2A v1.0 | a2a_signing_key_lifecycle | 4 | 1 |
| `generic.a2a_protocol_compromise` | Generic | Agentic AI | a2a_protocol_compromise | 5 | 1 |
| `generic.agent_harness_compromise` | Generic | Agentic AI | agent_harness_compromise | 7 | 0 |
| `generic.agent_session_hijack` | Generic | Agentic AI | agent_session_hijack | 5 | 0 |
| `generic.ai_cache_poisoning` | Generic | Agentic AI | ai_cache_poisoning | 5 | 0 |
| `generic.browser_computer_use` | Generic | Agentic AI | browser_computer_use | 6 | 1 |
| `generic.cross_tenant_context_bleed` | Generic | Agentic AI | cross_tenant_context_bleed | 5 | 0 |
| `generic.model_router_drift` | Generic | Agentic AI | model_router_drift | 4 | 1 |
| `generic.output_rendering_active_content` | Generic | Agentic AI | output_rendering_active_content | 4 | 1 |
| `generic.outstanding_delegated_work` | Generic | Agentic AI | outstanding_delegated_work | 4 | 1 |
| `generic.prompt_self_replication` | Generic | Agentic AI | prompt_self_replication | 4 | 1 |
| `generic.tool_identity_shadowing` | Generic | Agentic AI | tool_identity_shadowing | 3 | 1 |
| `generic.workspace_instruction_poisoning` | Generic | Agentic AI | workspace_instruction_poisoning | 4 | 1 |
| `mcp.authorization_compromise` | Generic | Agentic AI | mcp_authorization_compromise | 3 | 0 |
| `mcp.catalog_cache_poisoning` | Generic | Agentic AI | mcp_catalog_cache_poisoning | 3 | 0 |
| `mcp.instruction_poisoning` | Generic | Agentic AI | mcp_instruction_poisoning | 3 | 0 |
| `mcp.root_escape` | Generic | Agentic AI | mcp_root_escape | 3 | 0 |
| `mcp.task_abuse` | Generic | Agentic AI | mcp_task_abuse | 3 | 0 |
| `anthropic.claude_code.prompt_injection` | Anthropic | Claude Code | prompt_injection | 9 | 7 |
| `enterprise.a2a_request_provenance` | Generic | Enterprise AI-DFIR | a2a_request_provenance | 4 | 0 |
| `enterprise.case_export` | Generic | Enterprise AI-DFIR | case_export | 3 | 1 |
| `enterprise.distributed_collection` | Generic | Enterprise AI-DFIR | distributed_collection | 4 | 0 |
| `enterprise.dr_restore` | Generic | Enterprise AI-DFIR | dr_restore | 2 | 1 |
| `enterprise.kms_envelope_integrity` | Generic | Enterprise AI-DFIR | kms_envelope_integrity | 2 | 1 |
| `enterprise.legal_hold` | Generic | Enterprise AI-DFIR | legal_hold | 2 | 1 |
| `enterprise.metadata_integrity` | Generic | Enterprise AI-DFIR | metadata_integrity | 3 | 0 |
| `enterprise.native_provider_collection` | Generic | Enterprise AI-DFIR | native_provider_collection | 3 | 1 |
| `enterprise.object_storage_integrity` | Generic | Enterprise AI-DFIR | object_storage_integrity | 2 | 1 |
| `enterprise.oidc_identity` | Generic | Enterprise AI-DFIR | oidc_identity | 3 | 0 |
| `enterprise.production_readiness` | Generic | Enterprise AI-DFIR | production_readiness | 3 | 0 |
| `enterprise.provider_collection_gap` | Generic | Enterprise AI-DFIR | provider_collection_gap | 3 | 0 |
| `enterprise.scale_capacity` | Generic | Enterprise AI-DFIR | scale_capacity | 2 | 1 |
| `enterprise.spiffe_service_identity` | Generic | Enterprise AI-DFIR | spiffe_service_identity | 3 | 0 |
| `generic.api_model_incident` | Generic | Any | api_model_incident | 4 | 1 |
| `generic.mcp_compromise` | Generic | Any | mcp_compromise | 5 | 0 |
| `agentic.mcp.protocol_compromise.2026_07_28` | Model Context Protocol | MCP | mcp_compromise | 5 | 2 |
| `generic.memory_poisoning` | Generic | Any | memory_poisoning | 4 | 0 |
| `generic.rag_poisoning` | Generic | Any | rag_poisoning | 5 | 0 |
| `microsoft.agent365.ai_threat_detection` | Microsoft | Microsoft Defender XDR / Agent 365 | agentic_ai_threat | 5 | 8 |
| `microsoft.defender_endpoint.suspicious_ai_prompt_injection` | Microsoft | Microsoft Defender for Endpoint | prompt_injection | 5 | 1 |
| `microsoft.AI.AIModelScan_MalwareDetected` | Microsoft | Microsoft Defender for Cloud AI workloads | model_supply_chain | 8 | 7 |
| `microsoft.AI.Azure_ASCIISmuggling` | Microsoft | Microsoft Defender for Cloud AI workloads | indirect_prompt_injection | 8 | 6 |
| `microsoft.AI.Azure_AccessAnomaly` | Microsoft | Microsoft Defender for Cloud AI workloads | suspicious_access | 6 | 6 |
| `microsoft.AI.Azure_AccessFromAnonymizedIP` | Microsoft | Microsoft Defender for Cloud AI workloads | suspicious_access | 6 | 6 |
| `microsoft.AI.Azure_AccessFromSuspiciousIP` | Microsoft | Microsoft Defender for Cloud AI workloads | suspicious_access | 6 | 6 |
| `microsoft.AI.Azure_AccessFromSuspiciousUserAgent` | Microsoft | Microsoft Defender for Cloud AI workloads | suspicious_access | 6 | 6 |
| `microsoft.AI.Azure_AnomalousOperation.InitialAccess` | Microsoft | Microsoft Defender for Cloud AI workloads | identity_compromise | 6 | 6 |
| `microsoft.AI.Azure_AnomalousToolInvocation` | Microsoft | Microsoft Defender for Cloud AI workloads | tool_abuse | 8 | 6 |
| `microsoft.AI.Azure_CredentialTheftAttempt` | Microsoft | Microsoft Defender for Cloud AI workloads | credential_exposure | 6 | 7 |
| `microsoft.AI.Azure_DOWDuplicateRequests` | Microsoft | Microsoft Defender for Cloud AI workloads | cost_abuse | 7 | 6 |
| `microsoft.AI.Azure_DOWVolumeAnomaly` | Microsoft | Microsoft Defender for Cloud AI workloads | cost_abuse | 7 | 6 |
| `microsoft.AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt` | Microsoft | Microsoft Defender for Cloud AI workloads | direct_prompt_injection | 6 | 6 |
| `microsoft.AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt` | Microsoft | Microsoft Defender for Cloud AI workloads | direct_prompt_injection | 7 | 6 |
| `microsoft.AI.Azure_LLMReconnaissance` | Microsoft | Microsoft Defender for Cloud AI workloads | llm_reconnaissance | 5 | 7 |
| `microsoft.AI.Azure_MaliciousUrl.ModelResponse` | Microsoft | Microsoft Defender for Cloud AI workloads | malicious_content_propagation | 6 | 7 |
| `microsoft.AI.Azure_MaliciousUrl.UnknownSource` | Microsoft | Microsoft Defender for Cloud AI workloads | malicious_content_propagation | 6 | 7 |
| `microsoft.AI.Azure_MaliciousUrl.UserPrompt` | Microsoft | Microsoft Defender for Cloud AI workloads | prompt_poisoning | 6 | 7 |
| `microsoft.ExposedKubernetesService.AI` | Microsoft | Microsoft Defender for Cloud / Defender for Containers | ai_infrastructure_exposure | 8 | 6 |
| `microsoft.purview.ai_interaction` | Microsoft | Microsoft Purview DSPM for AI / Audit | ai_data_security | 4 | 2 |
| `owasp.agentic.asi01` | OWASP | Agentic AI | agent_goal_hijack | 5 | 1 |
| `owasp.agentic.asi02` | OWASP | Agentic AI | tool_misuse | 4 | 1 |
| `owasp.agentic.asi03` | OWASP | Agentic AI | identity_privilege_abuse | 5 | 0 |
| `owasp.agentic.asi04` | OWASP | Agentic AI | agentic_supply_chain | 4 | 1 |
| `owasp.agentic.asi05` | OWASP | Agentic AI | unexpected_code_execution | 4 | 2 |
| `owasp.agentic.asi06` | OWASP | Agentic AI | memory_context_poisoning | 5 | 1 |
| `owasp.agentic.asi07` | OWASP | Agentic AI | insecure_inter_agent_communication | 5 | 0 |
| `owasp.agentic.asi08` | OWASP | Agentic AI | cascading_failures | 5 | 0 |
| `owasp.agentic.asi09` | OWASP | Agentic AI | human_agent_trust_exploitation | 4 | 1 |
| `owasp.agentic.asi10` | OWASP | Agentic AI | rogue_agents | 6 | 1 |
| `generic.agent_exfil_channel` | Generic | AI Content / Agent Execution | agent_exfil_channel | 3 | 1 |
| `generic.agent_workspace_archive_intake` | Generic | AI Coding Agent / IDE | agent_workspace_archive_intake | 2 | 2 |
| `generic.ai_ide_autoload_surface` | Generic | AI Content / Agent Execution | ai_ide_autoload_surface | 3 | 2 |
| `generic.approval_trust_toctou` | Generic | AI Content / Agent Execution | approval_trust_toctou | 4 | 1 |
| `generic.evil_font_glyph_deception` | Generic | AI Content / Agent Execution | evil_font_glyph_deception | 5 | 2 |
| `generic.hidden_document_representation` | Generic | AI Content / Agent Execution | hidden_document_representation | 5 | 0 |
| `generic.hidden_markup_source` | Generic | AI Content / Agent Execution | hidden_markup_source | 3 | 1 |
| `generic.session_history_tampering` | Generic | AI Content / Agent Execution | session_history_tampering | 4 | 1 |
| `generic.terminal_control_deception` | Generic | AI Content / Agent Execution | terminal_control_deception | 2 | 2 |
| `generic.unicode_representation_smuggling` | Generic | AI Content / Agent Execution | unicode_representation_smuggling | 3 | 1 |
| `runtime.analyst_governance` | Generic | AI Runtime / Agentic Systems | analyst_governance_failure | 4 | 0 |
| `runtime.behavioral_sandbox` | Generic | AI Runtime / Agentic Systems | behavioral_sandbox_drift | 4 | 0 |
| `runtime.causal_graph` | Generic | AI Runtime / Agentic Systems | causal_evidence_gap | 2 | 1 |
| `runtime.collector_health` | Generic | AI Runtime / Agentic Systems | collector_health_failure | 3 | 0 |
| `runtime.credential_lineage` | Generic | AI Runtime / Agentic Systems | credential_lineage_abuse | 3 | 1 |
| `runtime.export_redaction` | Generic | AI Runtime / Agentic Systems | export_redaction_integrity | 3 | 0 |
| `runtime.mcp_2026_integrity` | Generic | AI Runtime / Agentic Systems | mcp_2026_integrity | 3 | 1 |
| `runtime.memory_integrity` | Generic | AI Runtime / Agentic Systems | persistent_memory_integrity | 3 | 1 |
| `runtime.otel_genai` | Generic | AI Runtime / Agentic Systems | otel_genai_coverage | 3 | 0 |
| `runtime.provider_telemetry` | Generic | AI Runtime / Agentic Systems | provider_telemetry_gap | 3 | 0 |
| `runtime.skill_supply_chain` | Generic | AI Runtime / Agentic Systems | skill_supply_chain | 3 | 1 |
| `runtime.temporal_authority` | Generic | AI Runtime / Agentic Systems | temporal_authority_violation | 3 | 1 |
| `runtime.transparency_anchor` | Generic | AI Runtime / Agentic Systems | transparency_anchor_failure | 3 | 0 |
| `runtime.workload_identity` | Generic | AI Runtime / Agentic Systems | workload_identity_anomaly | 3 | 1 |
