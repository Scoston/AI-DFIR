# Production Architecture v1.6

Recommended trust zones: analyst access, API/control plane, collector plane, metadata database, evidence object store, KMS/HSM, identity plane, monitoring/assurance plane. Default deny between zones and authorize only documented paths. The Workbench should not hold cloud-provider credentials and should not have direct raw-object delete permissions.
