CREATE TABLE IF NOT EXISTS platform_assurance_runs(
  assurance_id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(tenant_id), created_utc timestamptz NOT NULL DEFAULT now(), status text NOT NULL, report jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_certifications(
  certification_id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(tenant_id), provider text NOT NULL, adapter text NOT NULL, api_version text, certified boolean NOT NULL, validated_utc timestamptz NOT NULL, report jsonb NOT NULL
);
ALTER TABLE platform_assurance_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_assurance_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS platform_assurance_tenant ON platform_assurance_runs;
CREATE POLICY platform_assurance_tenant ON platform_assurance_runs USING (tenant_id=current_setting('app.tenant_id',true)) WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
ALTER TABLE provider_certifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_certifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_certifications_tenant ON provider_certifications;
CREATE POLICY provider_certifications_tenant ON provider_certifications USING (tenant_id=current_setting('app.tenant_id',true)) WITH CHECK (tenant_id=current_setting('app.tenant_id',true));
