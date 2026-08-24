# Azure Deployment Mapping

- Metadata: approved HA PostgreSQL.
- Evidence: immutable Blob Storage/WORM using an equivalent adapter/control.
- KEK: Azure Key Vault through the `azure_key_vault` adapter.
- Identity: Entra ID/OIDC plus managed/workload identity for collectors.
- Collection: Microsoft Graph Security and Azure AI/Foundry diagnostics.

Verify diagnostic categories and retention before incidents occur.
