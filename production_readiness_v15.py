#!/usr/bin/env python3
"""Evidence-backed production readiness validator for AI-DFIR v1.5."""
from __future__ import annotations
import argparse,json,os
from datetime import datetime,timezone,timedelta
from pathlib import Path

def _load(p):return json.loads(Path(p).read_text()) if p and Path(p).exists() else None
def _sha(p):
    import hashlib
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def _recent(ts,max_days):
    try:return datetime.now(timezone.utc)-datetime.fromisoformat(ts.replace('Z','+00:00'))<=timedelta(days=max_days)
    except Exception:return False

def assess(cfg):
    findings=[];checks=[]
    def check(name,ok,details=None,severity='critical'):
        checks.append({'control':name,'pass':bool(ok),'details':details})
        if not ok:findings.append({'type':'production_control_unverified','severity':severity,'control':name,'details':details})
    # Metadata backend: production requires PostgreSQL and a live schema probe.
    dsn=(cfg.get('metadata_store') or {}).get('dsn','')
    db_ok=False;db_details={'dsn_type':'postgres' if dsn.startswith(('postgresql://','postgres://')) else 'other'}
    if dsn.startswith(('postgresql://','postgres://')):
        try:
            import psycopg
            with psycopg.connect(dsn,connect_timeout=5) as c:
                with c.cursor() as cur:cur.execute('SELECT version FROM schema_meta LIMIT 1');v=cur.fetchone()[0];db_ok=int(v)>=15;db_details['schema_version']=int(v)
                with c.cursor() as cur:
                    cur.execute("SELECT count(*) FROM pg_policies WHERE policyname IN ('tenants_tenant','cases_tenant','evidence_tenant','tasks_tenant','collectors_tenant','holds_tenant','audit_tenant')");db_details['rls_policy_count']=int(cur.fetchone()[0])
                    db_ok=db_ok and db_details['rls_policy_count']>=7
                    cur.execute("SELECT count(*) FROM pg_class WHERE relname IN ('tenants','cases','evidence_meta','acquisition_tasks','collector_nodes','legal_holds','audit_events') AND relrowsecurity AND relforcerowsecurity")
                    db_details['force_rls_table_count']=int(cur.fetchone()[0]);db_ok=db_ok and db_details['force_rls_table_count']>=7
                    cur.execute('SELECT pg_is_in_recovery()');in_recovery=bool(cur.fetchone()[0]);db_details['in_recovery']=in_recovery
                    min_replicas=int((cfg.get('metadata_store') or {}).get('min_streaming_replicas',1))
                    if in_recovery:
                        # A replica endpoint cannot prove primary-side replica count. Require an independently generated HA probe.
                        ha_probe=_load((cfg.get('metadata_store') or {}).get('ha_probe_result'));db_details['ha_probe']=ha_probe
                        ha_ok=bool(ha_probe and ha_probe.get('valid') is True and int(ha_probe.get('streaming_replicas',0))>=min_replicas)
                    else:
                        try:
                            cur.execute("SELECT count(*) FROM pg_stat_replication WHERE state='streaming'");replicas=int(cur.fetchone()[0])
                        except Exception:replicas=0
                        db_details['streaming_replicas']=replicas;ha_ok=replicas>=min_replicas
                    db_ok=db_ok and ha_ok
        except Exception as e:db_details['probe_error']=repr(e)
    check('postgresql_ha_metadata_and_rls',db_ok,db_details)
    # Immutable object storage.
    oscfg=cfg.get('object_store') or {};obj_ok=False;od={'backend':oscfg.get('backend')}
    if oscfg.get('backend')=='s3_object_lock':
        try:
            import boto3
            c=boto3.client('s3',region_name=oscfg.get('region'),endpoint_url=oscfg.get('endpoint_url'))
            c.head_bucket(Bucket=oscfg['bucket']);lock=c.get_object_lock_configuration(Bucket=oscfg['bucket']).get('ObjectLockConfiguration',{});od['object_lock']=lock;default=((lock.get('Rule') or {}).get('DefaultRetention') or {});od['default_retention']=default;min_days=int(oscfg.get('min_retention_days',365));ret_days=int(default.get('Days') or 0)+(int(default.get('Years') or 0)*365);obj_ok=lock.get('ObjectLockEnabled')=='Enabled' and default.get('Mode')=='COMPLIANCE' and ret_days>=min_days
        except Exception as e:od['probe_error']=repr(e)
    check('immutable_object_storage',obj_ok,od)
    # KMS/HSM: describe the configured key; local test KEKs are rejected.
    k=cfg.get('key_management') or {};kms_ok=False;kd={'provider':k.get('provider'),'key_id':k.get('key_id')}
    if k.get('provider')=='aws_kms':
        try:
            import boto3
            client=boto3.client('kms',region_name=k.get('region'));meta=client.describe_key(KeyId=k['key_id'])['KeyMetadata'];kd['key_state']=meta.get('KeyState');kd['key_manager']=meta.get('KeyManager');kms_ok=meta.get('Enabled') is True and meta.get('KeyState')=='Enabled';
            if meta.get('KeyManager')=='CUSTOMER':
                try:rot=client.get_key_rotation_status(KeyId=k['key_id']).get('KeyRotationEnabled');kd['rotation_enabled']=rot;kms_ok=kms_ok and bool(rot)
                except Exception as e:kd['rotation_probe_error']=repr(e);kms_ok=False
        except Exception as e:kd['probe_error']=repr(e)
    elif k.get('provider') in ('azure_key_vault','google_cloud_kms'):
        # A deployment-generated probe artifact proves the organization-specific adapter was tested.
        probe=_load(k.get('probe_result'));kd['probe_result']=probe;kms_ok=bool(probe and probe.get('valid') is True and probe.get('provider')==k.get('provider'))
    check('kms_hsm_key_management',kms_ok,kd)
    # Enterprise user identity: pinned OIDC or signed upstream SAML/OIDC gateway envelope.
    identity=cfg.get('identity') or {};mode=identity.get('mode','oidc');id_ok=False;id_details={'mode':mode}
    if mode=='oidc':
        oidc=cfg.get('oidc') or identity.get('oidc') or {};jwks_file=oidc.get('jwks_file');jwks=_load(jwks_file);actual_jwks_sha=_sha(jwks_file) if jwks_file and Path(jwks_file).exists() else None;oidc_probe=_load(oidc.get('last_probe'))
        id_ok=bool(oidc.get('issuer') and oidc.get('audience') and jwks and jwks.get('keys') and oidc.get('jwks_sha256') and actual_jwks_sha==oidc.get('jwks_sha256') and oidc_probe and oidc_probe.get('schema')=='ai-dfir/oidc-principal/v1.5' and oidc_probe.get('trusted') is True and oidc_probe.get('issuer')==oidc.get('issuer'))
        id_details.update({'issuer':oidc.get('issuer'),'audience':oidc.get('audience'),'key_count':len((jwks or {}).get('keys',[])),'expected_jwks_sha256':oidc.get('jwks_sha256'),'actual_jwks_sha256':actual_jwks_sha,'last_probe':oidc_probe})
    elif mode=='signed_gateway':
        gw=cfg.get('signed_gateway') or identity.get('signed_gateway') or {};pub=gw.get('public_key');actual=_sha(pub) if pub and Path(pub).exists() else None;probe=_load(gw.get('last_probe'))
        id_ok=bool(pub and gw.get('public_key_sha256') and actual==gw.get('public_key_sha256') and probe and probe.get('schema')=='ai-dfir/trusted-identity-validation/v1.5' and probe.get('valid') is True)
        id_details.update({'public_key':pub,'expected_public_key_sha256':gw.get('public_key_sha256'),'actual_public_key_sha256':actual,'last_probe':probe})
    check('enterprise_user_identity',id_ok,id_details)
    svc=cfg.get('service_identity') or {};bundle=svc.get('trust_bundle');actual_bundle_sha=_sha(bundle) if bundle and Path(bundle).exists() else None;svc_probe=_load(svc.get('last_probe'))
    svc_ok=bool(svc.get('mode')=='spiffe_mtls' and bundle and Path(bundle).exists() and svc.get('trust_bundle_sha256') and actual_bundle_sha==svc.get('trust_bundle_sha256') and svc_probe and svc_probe.get('schema')=='ai-dfir/spiffe-mtls-identity/v1.5' and svc_probe.get('trusted') is True)
    check('spiffe_mtls_service_identity',svc_ok,{'mode':svc.get('mode'),'trust_bundle':bundle,'expected_sha256':svc.get('trust_bundle_sha256'),'actual_sha256':actual_bundle_sha,'last_probe':svc_probe})
    # DR, external transparency, analyst audit and peer review proof artifacts.
    dr=_load((cfg.get('backup_dr') or {}).get('last_restore_validation'));dr_ok=bool(dr and dr.get('valid') is True and _recent(dr.get('validated_utc') or dr.get('created_utc',''),(cfg.get('backup_dr') or {}).get('max_age_days',90)))
    check('tested_restore',dr_ok,dr)
    tr=_load((cfg.get('transparency') or {}).get('last_receipt_validation'));tr_ok=bool(tr and tr.get('valid') is True and str(tr.get('schema','')).startswith('ai-dfir/transparency-receipt-validation/'))
    check('external_transparency_receipt',tr_ok,tr)
    aa=_load((cfg.get('analyst_audit') or {}).get('last_validation'));check('signed_analyst_audit',bool(aa and aa.get('valid') is True and str(aa.get('schema','')).startswith('ai-dfir/analyst-action-audit/')),aa)
    pr=cfg.get('peer_review') or {};pr_probe=_load(pr.get('last_probe'));check('independent_peer_review_policy',pr.get('required_for_critical') is True and bool(pr_probe and pr_probe.get('ready') is True and str(pr_probe.get('schema','')).startswith('ai-dfir/peer-review-gate/')),{**pr,'last_probe_result':pr_probe})
    red=cfg.get('redaction') or {};red_probe=_load(red.get('last_validation'));check('deterministic_redaction',red.get('enabled') is True and red.get('manifest_required') is True and bool(red_probe and red_probe.get('schema')=='ai-dfir/redaction-validation/v1.5' and red_probe.get('valid') is True),{**red,'last_validation_result':red_probe})
    # Provider collector health: every provider required by deployment must report complete mandatory collection.
    phealth=[];providers_ok=True
    for f in (cfg.get('provider_gap_results') or []):
        r=_load(f);phealth.append(r)
        if not r or r.get('complete_mandatory') is not True:providers_ok=False
    check('provider_mandatory_collection_health',providers_ok and bool(phealth),phealth)
    # Network/workbench and operational SLO declarations with probe evidence.
    wb=cfg.get('workbench') or {};wb_probe=_load(wb.get('auth_probe_result'));local_only=wb.get('bind') in ('127.0.0.1','localhost');gateway_ok=local_only or (wb.get('behind_authenticated_gateway') is True and bool(wb_probe and wb_probe.get('schema')=='ai-dfir/gateway-auth-probe/v1.5' and wb_probe.get('valid') is True));check('authenticated_workbench_gateway',gateway_ok,{**wb,'auth_probe':wb_probe})
    slo=_load((cfg.get('service_slo') or {}).get('last_probe'));check('service_slo_probe',bool(slo and slo.get('pass') is True and slo.get('schema')=='ai-dfir/service-slo/v1.5'),slo)
    dist=_load((cfg.get('distributed_acquisition') or {}).get('last_receipt_validation'));check('distributed_acquisition_signed_receipt',bool(dist and dist.get('schema')=='ai-dfir/acquisition-receipt-validation/v1.5' and dist.get('valid') is True),dist)
    hold=_load((cfg.get('legal_hold') or {}).get('last_probe'));check('legal_hold_lifecycle',bool(hold and hold.get('valid') is True and hold.get('schema')=='ai-dfir/legal-hold-enforcement/v1.5'),hold)
    export=_load((cfg.get('case_export') or {}).get('last_validation'));check('signed_case_export',bool(export and export.get('schema')=='ai-dfir/case-export-validation/v1.5' and export.get('valid') is True),export)
    scale=_load((cfg.get('capacity') or {}).get('last_benchmark'));min_w=float((cfg.get('capacity') or {}).get('min_write_ops_per_sec',100));min_r=float((cfg.get('capacity') or {}).get('min_read_ops_per_sec',500));scale_ok=bool(scale and scale.get('backend')=='postgres' and scale.get('deployment_benchmark') is True and float(scale.get('write_ops_per_sec',0))>=min_w and float(scale.get('read_ops_per_sec',0))>=min_r);check('capacity_benchmark',scale_ok,scale)
    return {'schema':'ai-dfir/production-readiness/v1.5','production_ready':not any(x['severity']=='critical' for x in findings),'checks':checks,'findings':findings,
            'rule':'v1.5 requires evidence-backed control probes. Declared infrastructure without a successful probe is UNVERIFIED.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--out');a=ap.parse_args();o=assess(json.loads(Path(a.config).read_text()));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['production_ready'] else 2)
if __name__=='__main__':main()
