CREATE TABLE IF NOT EXISTS schema_meta(version integer NOT NULL);
INSERT INTO schema_meta(version) SELECT 15 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);
DO $$ BEGIN IF EXISTS (SELECT 1 FROM schema_meta WHERE version <> 15) THEN RAISE EXCEPTION 'unsupported AI-DFIR metadata schema'; END IF; END $$;
CREATE TABLE IF NOT EXISTS tenants(tenant_id text PRIMARY KEY,name text,created_utc text NOT NULL);
CREATE TABLE IF NOT EXISTS cases(tenant_id text NOT NULL,case_id text NOT NULL,title text,severity text,status text NOT NULL,created_utc text NOT NULL,updated_utc text NOT NULL,metadata_json text,PRIMARY KEY(tenant_id,case_id));
CREATE TABLE IF NOT EXISTS evidence_meta(tenant_id text NOT NULL,evidence_id text NOT NULL,case_id text NOT NULL,sha256 text NOT NULL,size_bytes bigint NOT NULL,media_type text,classification text,object_uri text NOT NULL,acquisition_receipt_sha256 text,created_utc text NOT NULL,metadata_json text,PRIMARY KEY(tenant_id,evidence_id));
CREATE INDEX IF NOT EXISTS evidence_case_idx ON evidence_meta(tenant_id,case_id);
CREATE INDEX IF NOT EXISTS evidence_sha_idx ON evidence_meta(tenant_id,sha256);
CREATE TABLE IF NOT EXISTS acquisition_tasks(tenant_id text NOT NULL,task_id text NOT NULL,case_id text NOT NULL,collector_type text NOT NULL,state text NOT NULL,lease_owner text,lease_until_utc text,attempt integer NOT NULL DEFAULT 0,request_json text NOT NULL,receipt_json text,created_utc text NOT NULL,updated_utc text NOT NULL,PRIMARY KEY(tenant_id,task_id));
CREATE INDEX IF NOT EXISTS task_state_idx ON acquisition_tasks(tenant_id,state);
CREATE TABLE IF NOT EXISTS collector_nodes(tenant_id text NOT NULL,collector_id text NOT NULL,public_key_fingerprint text,capabilities_json text,enabled integer NOT NULL DEFAULT 1,last_seen_utc text,metadata_json text,PRIMARY KEY(tenant_id,collector_id));
CREATE TABLE IF NOT EXISTS legal_holds(tenant_id text NOT NULL,hold_id text NOT NULL,case_id text NOT NULL,status text NOT NULL,reason text NOT NULL,created_by text NOT NULL,created_utc text NOT NULL,released_by text,released_utc text,metadata_json text,PRIMARY KEY(tenant_id,hold_id));
CREATE TABLE IF NOT EXISTS audit_events(seq bigserial PRIMARY KEY,tenant_id text NOT NULL,actor text NOT NULL,action text NOT NULL,object_type text,object_id text,created_utc text NOT NULL,details_json text);

-- Defense in depth: every tenant-bearing metadata table is protected by RLS.
-- FORCE ROW LEVEL SECURITY prevents the ordinary application table owner from
-- accidentally bypassing isolation. A separate break-glass/admin DB role may
-- use PostgreSQL BYPASSRLS under audited operational procedures.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY; ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE cases ENABLE ROW LEVEL SECURITY; ALTER TABLE cases FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_meta ENABLE ROW LEVEL SECURITY; ALTER TABLE evidence_meta FORCE ROW LEVEL SECURITY;
ALTER TABLE acquisition_tasks ENABLE ROW LEVEL SECURITY; ALTER TABLE acquisition_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE collector_nodes ENABLE ROW LEVEL SECURITY; ALTER TABLE collector_nodes FORCE ROW LEVEL SECURITY;
ALTER TABLE legal_holds ENABLE ROW LEVEL SECURITY; ALTER TABLE legal_holds FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='tenants_tenant') THEN
    CREATE POLICY tenants_tenant ON tenants USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='cases_tenant') THEN
    CREATE POLICY cases_tenant ON cases USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='evidence_tenant') THEN
    CREATE POLICY evidence_tenant ON evidence_meta USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='tasks_tenant') THEN
    CREATE POLICY tasks_tenant ON acquisition_tasks USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='collectors_tenant') THEN
    CREATE POLICY collectors_tenant ON collector_nodes USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='holds_tenant') THEN
    CREATE POLICY holds_tenant ON legal_holds USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname='audit_tenant') THEN
    CREATE POLICY audit_tenant ON audit_events USING (tenant_id=current_setting('app.tenant_id', true)) WITH CHECK (tenant_id=current_setting('app.tenant_id', true));
  END IF;
END $$;
