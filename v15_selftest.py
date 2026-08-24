#!/usr/bin/env python3
from __future__ import annotations
import base64,hashlib,json,os,shutil,subprocess,sys,time,zipfile
from datetime import datetime,timezone,timedelta
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))

from enterprise_metadata_store import MetadataStore
from tenant_policy_v15 import authorize
from oidc_identity_v15 import verify_token
from spiffe_mtls_v15 import verify_svid
from kms_envelope_v15 import LocalKEK,encrypt_file,decrypt_file,file_sha256
from object_store_v15 import LocalImmutableStore
from enterprise_evidence_ingest_v15 import ingest as protected_ingest
from fleet_crypto import generate
from distributed_acquisition_v15 import create_request,enqueue,verify_receipt
from collector_worker_v15 import run_once
from legal_hold_v15 import create as hold_create,release as hold_release,validate as hold_validate
from legal_hold_apply_v15 import apply as hold_apply
from dr_integrity_v15 import create as dr_create,validate as dr_validate
from case_export_v15 import export_case,verify_export
from provider_gap_analysis_v15 import analyze as gap_analyze
from local_agent_collectors_v15 import collect as local_collect
from service_slo_v15 import assess as slo_assess
from scale_benchmark_v15 import run as scale_run
from production_readiness_v15 import assess as readiness_assess
from redaction_validation_v15 import validate as redaction_validate
from evidence_redaction import redact
from a2a_request_provenance_v15 import create as a2a_req_create,verify as a2a_req_verify
from evidence_pack_engine import load_packs
from case_model import full_case
import provider_collectors_v15 as pc


def writej(p,o):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True),encoding='utf-8')
def b64u_int(n):return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,'big')).rstrip(b'=').decode()

def make_oidc(out):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=priv.public_key().public_numbers();kid='oidc-test'
    jwks={'keys':[{'kty':'RSA','kid':kid,'alg':'RS256','use':'sig','n':b64u_int(pub.n),'e':b64u_int(pub.e)}]}
    now=int(time.time());claims={'sub':'alice','iss':'https://issuer.example','aud':'ai-dfir','iat':now-7200,'exp':now-3600,'tenant_id':'T1','roles':['investigator']}
    tok=jwt.encode(claims,priv,algorithm='RS256',headers={'kid':kid});return tok,jwks,now-5400

def make_spiffe(out):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'AI-DFIR Test CA')])
    ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True).sign(ca_key,hashes.SHA256())
    leaf_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'collector-1')])
    leaf=x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(hours=8)).add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('spiffe://example.org/collector/1')]),critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False).sign(ca_key,hashes.SHA256())
    ca_p=out/'ca.pem';leaf_p=out/'leaf.pem';ca_p.write_bytes(ca.public_bytes(serialization.Encoding.PEM));leaf_p.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    # CRL revoked 100s ago.
    rev=x509.RevokedCertificateBuilder().serial_number(leaf.serial_number).revocation_date(now-timedelta(seconds=100)).build()
    crl=x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now-timedelta(minutes=1)).next_update(now+timedelta(days=1)).add_revoked_certificate(rev).sign(ca_key,hashes.SHA256())
    crl_p=out/'ca.crl.pem';crl_p.write_bytes(crl.public_bytes(serialization.Encoding.PEM));return leaf_p,ca_p,crl_p,now

class FakeResp:
    def __init__(self,obj,headers=None,status=200):self._obj=obj;self.headers=headers or {};self.status_code=status
    def raise_for_status(self):
        if self.status_code>=400:raise RuntimeError(self.status_code)
    def json(self):return self._obj

def fake_provider_request(method,url,headers=None,params=None,json=None,timeout=None):
    u=str(url);params=params or {};json=json or {}
    if 'graph.microsoft.com' in u:
        if 'skiptoken=2' in u:return FakeResp({'value':[{'id':'m2'}]})
        return FakeResp({'value':[{'id':'m1'}],'@odata.nextLink':'https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken=2'})
    if 'api.anthropic.com/v1/compliance/activities' in u:
        if params.get('after_id'):return FakeResp({'data':[{'id':'a2'}],'has_more':False})
        return FakeResp({'data':[{'id':'a1'}],'has_more':True,'last_id':'a1'})
    if 'api.openai.com/v1/organization/usage' in u:
        if params.get('page'):return FakeResp({'data':[{'x':2}],'has_more':False})
        return FakeResp({'data':[{'x':1}],'has_more':True,'next_page':'p2'},{'x-request-id':'req1'})
    if 'logging.googleapis.com' in u:
        if json.get('pageToken'):return FakeResp({'entries':[{'id':'g2'}]})
        return FakeResp({'entries':[{'id':'g1'}],'nextPageToken':'g2'})
    if 'api.github.com' in u:
        if 'page=2' in u:return FakeResp([{'action':'copilot.second'}])
        return FakeResp([{'action':'copilot.first'}],{'Link':'<https://api.github.com/enterprises/acme/audit-log?page=2>; rel="next"'})
    raise AssertionError('unexpected provider URL '+u)

def main():
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);a=ap.parse_args();out=Path(a.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True);r={}

    packs=load_packs();assert len(packs)>=96;r['evidence_pack_catalog_96']='PASS'

    # Metadata tenant isolation + registered collector leasing.
    db=out/'meta.db';dsn='sqlite:///'+str(db);s=MetadataStore(dsn);s.ensure_tenant('T1');s.ensure_tenant('T2');s.create_case('T1','C1');s.create_case('T2','C2')
    assert s.get_case('T1','C2') is None
    try:s.claim_task('T1','unknown',['filesystem_snapshot']);raise AssertionError('unenrolled collector claimed task')
    except PermissionError:pass
    s.register_collector('T1','COL1','fp',['filesystem_snapshot'],{'spiffe_id':'spiffe://example.org/collector/1'})
    r['tenant_isolation_and_collector_enrollment']='PASS'

    # OIDC historical validation and tenant RBAC.
    token,jwks,eval_t=make_oidc(out);principal=verify_token(token,jwks,'https://issuer.example','ai-dfir',evaluation_time=eval_t)
    assert principal['trusted'] and authorize(principal,'T1','case:read')['allowed'] and not authorize(principal,'T2','case:read')['allowed']
    assert not verify_token(token,jwks,'https://issuer.example','ai-dfir')['trusted']
    r['oidc_incident_time_and_tenant_rbac']='PASS'

    # SPIFFE historical revocation.
    leaf,ca,crl,now=make_spiffe(out)
    before=(now-timedelta(seconds=200)).isoformat();after=now.isoformat()
    assert verify_svid(leaf,[ca],'example.org','spiffe://example.org/collector/1','client',before,[crl])['trusted']
    assert not verify_svid(leaf,[ca],'example.org','spiffe://example.org/collector/1','client',after,[crl])['trusted']
    r['spiffe_incident_time_crl']='PASS'

    # Chunked envelope encryption.
    source=out/'large.bin';source.write_bytes((b'AI-DFIR-EVIDENCE-'*400000)[:6*1024*1024]);enc=out/'large.enc';dec=out/'large.dec';kek=LocalKEK(bytes.fromhex('11'*32));encrypt_file(source,enc,kek);decrypt_file(enc,dec,kek);assert dec.read_bytes()==source.read_bytes() and enc.read_bytes().startswith(b'AIDFIR15E1\n')
    r['streamed_envelope_encryption']='PASS'

    # Protected enterprise ingest integrates encryption + immutable store + metadata.
    store_root=out/'objects';kcfg={'provider':'local-test','key_hex':'22'*32};ocfg={'backend':'local-immutable','root':str(store_root)}
    ing=protected_ingest(source,'T1','C1',dsn,kcfg,ocfg,legal_hold=True);ev=s.list_evidence('T1','C1');assert len(ev)==1 and ev[0]['sha256']==file_sha256(source) and ing['plaintext_uploaded_to_object_store'] is False
    objsha=ing['object']['sha256'];stored=store_root/'objects'/objsha[:2]/objsha;assert stored.read_bytes().startswith(b'AIDFIR15E1\n') and LocalImmutableStore(store_root).verify()['valid']
    r['protected_enterprise_evidence_ingest']='PASS'

    # Signed distributed acquisition + worker + receipt verification.
    req_priv=out/'req.pem';req_pub=out/'req.pub.pem';col_priv=out/'col.pem';col_pub=out/'col.pub.pem';generate(req_priv,req_pub);generate(col_priv,col_pub)
    snaproot=out/'snaproot';snaproot.mkdir();(snaproot/'one.txt').write_text('one')
    taskfile=out/'task.json';env=create_request('T1','C1','filesystem_snapshot',{'root':str(snaproot)},'alice',req_priv,taskfile);task=enqueue(dsn,taskfile,req_pub)
    wr=run_once(dsn,'T1','COL1',['filesystem_snapshot'],out/'worker',col_priv,out/'receipts',60,None,True);assert wr['status']=='COMPLETE'
    val=verify_receipt(wr['receipt'],col_pub,task['task_id']);assert val['valid']
    writej(out/'acquisition_receipt_validation.json',val);r['signed_distributed_acquisition']='PASS'

    # Provider pagination with fake network.
    old=pc.requests.request;pc.requests.request=fake_provider_request
    try:
        o,m,_=pc.microsoft_graph_security(token='x');assert m['collection_complete'] and m['page_count']==2
        o,m,_=pc.anthropic_compliance(token='x');assert m['collection_complete'] and m['page_count']==2
        o,m,_=pc.openai_org('usage',1,token='x');assert m['collection_complete'] and m['page_count']==2
        o,m,_=pc.google_cloud_logs('p','severity>=INFO',token='x');assert m['collection_complete'] and m['page_count']==2
        o,m,_=pc.github_copilot('acme',token='x');assert m['collection_complete'] and m['page_count']==2
    finally:pc.requests.request=old
    r['provider_native_pagination']='PASS'

    # Provider source gap remains explicit.
    gap=gap_analyze('microsoft',['graph_alerts_v2'],{'foundry_diagnostics':'not enabled'});assert not gap['complete_mandatory'] and any(x['type']=='mandatory_provider_source_unavailable' for x in gap['findings']);writej(out/'provider_evidence_gap_microsoft.json',gap);r['provider_gap_fail_closed']='PASS'

    # Local Claude acquisition.
    home=out/'home';proj=out/'proj';(home/'.claude').mkdir(parents=True);proj.mkdir();(home/'.claude/history.jsonl').write_text('{"x":1}\n');(proj/'CLAUDE.md').write_text('rules')
    lc=local_collect(home,proj,out/'localcap','claude_code');assert lc['count']>=2;r['local_agent_native_collection']='PASS'

    # Signed legal hold lifecycle and durable metadata hold state.
    hp=out/'hold.pem';hu=out/'hold.pub.pem';generate(hp,hu);hf=out/'hold.json';holdenv=hold_create('C1','T1','litigation','counsel',hp,hf);hv=hold_validate(hf,hu);assert hv['valid'] and hv['state']=='ACTIVE';payload=holdenv['payload'];s.put_legal_hold('T1','C1',payload['hold_id'],payload['reason'],payload['created_by']);assert s.active_holds('T1','C1')
    # Enforce the signed hold against durable metadata and immutable objects.
    hold_cfg={'backend':'local-immutable','root':str(store_root)}
    enforced=hold_apply(dsn,hf,hu,hold_cfg);assert enforced['valid'] and enforced['state']=='ACTIVE'
    obj_meta=json.loads((store_root/'meta'/(objsha+'.json')).read_text());assert obj_meta['legal_hold'] is True
    rf=out/'hold.release.json';hold_release(hf,hu,'counsel','released',hp,rf);hv2=hold_validate(hf,hu,rf,hu);assert hv2['valid'] and hv2['state']=='RELEASED'
    released=hold_apply(dsn,hf,hu,hold_cfg,rf,hu);assert released['valid'] and released['state']=='RELEASED'
    obj_meta=json.loads((store_root/'meta'/(objsha+'.json')).read_text());assert obj_meta['legal_hold'] is False
    assert not s.active_holds('T1','C1');writej(out/'legal_hold_validation.json',hv2);writej(out/'legal_hold_enforcement.json',released);r['signed_legal_hold_lifecycle_and_storage_enforcement']='PASS'

    # DR manifest/restore verification.
    bp=out/'backup.pem';bu=out/'backup.pub.pem';generate(bp,bu);backup_src=out/'backupsrc';backup_src.mkdir();(backup_src/'a.txt').write_text('A');mf=out/'backup.manifest.json';dr_create(backup_src,'B1',bp,mf);rest=out/'restore';shutil.copytree(backup_src,rest);dv=dr_validate(rest,mf,bu);assert dv['valid'] and dv.get('validated_utc');writej(out/'dr_restore_validation.json',dv);r['dr_restore_integrity']='PASS'

    # Signed tenant-scoped case export verification.
    case=out/'case';(case/'00_case').mkdir(parents=True);writej(case/'00_case/case.json',{'schema':'ai-dfir/case/v1.5','case_id':'CX','tenant_id':'T1','tool_version':'1.5'});(case/'note.txt').write_text('case note');ep=out/'export.pem';eu=out/'export.pub.pem';generate(ep,eu);ez=out/'case.zip';export_case(case,'T1','CX',ep,ez);exv=verify_export(ez,eu,'T1','CX');assert exv['valid'];writej(out/'case_export_validation.json',exv);r['signed_case_export']='PASS'

    # A2A request/response provenance.
    ap=out/'a2a.pem';au=out/'a2a.pub.pem';generate(ap,au);req=out/'req.json';resp=out/'resp.json';req.write_text('{"task":"T"}');resp.write_text('{"status":"ok"}');aenv=out/'a2a_request_provenance.json';a2a_req_create(req,resp,{'task_id':'T','context_id':'C','tenant_id':'T1','observed_utc':datetime.now(timezone.utc).isoformat()},ap,aenv);assert a2a_req_verify(aenv,au)['task_id']=='T';r['a2a_request_response_provenance']='PASS'

    # Redaction validation.
    raw=out/'secret.txt';raw.write_text('alice@example.com Bearer abcdefghijklmnop');redtxt,counts=redact(raw.read_text(),['bearer','email']);red=out/'secret.redacted.txt';red.write_text(redtxt);manifest={'schema':'ai-dfir/redaction-manifest/v1.4','source_sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),'redacted_sha256':hashlib.sha256(red.read_bytes()).hexdigest(),'types':['bearer','email'],'counts':counts};rm=out/'redaction.json';writej(rm,manifest);rv=redaction_validate(raw,red,rm);assert rv['valid'];writej(out/'redaction_validation.json',rv);r['deterministic_redaction_validation']='PASS'

    # SLO + reference scale and production-readiness fail-closed.
    slo=slo_assess([{'name':'collector','availability_percent':100,'max_ingest_lag_seconds':1,'error_percent':0}],{'default':{'min_availability_percent':99,'max_ingest_lag_seconds':60,'max_error_percent':1}});assert slo['pass'];writej(out/'service_slo.json',slo)
    scale=scale_run(150);assert scale['verified_records']==150 and scale['deployment_benchmark'] is False;writej(out/'scale_benchmark.json',scale);r['slo_and_capacity_reference']='PASS'
    rd=readiness_assess({});assert not rd['production_ready'] and rd['findings'];writej(out/'production_readiness_v15.json',rd);r['production_readiness_fail_closed']='PASS'

    # RLS schema covers all tenant-bearing tables and FORCE RLS.
    sql=(HERE/'postgres_schema_v15.sql').read_text();assert sql.count('FORCE ROW LEVEL SECURITY')>=7 and all(x in sql for x in ('collectors_tenant','holds_tenant','audit_tenant'));r['postgres_rls_defense_in_depth']='PASS'

    # Enterprise case integration and pack attachment.
    ic=out/'integrated_case';(ic/'00_case').mkdir(parents=True);writej(ic/'00_case/case.json',{'schema':'ai-dfir/case/v1.5','case_id':'ENT-1','tenant_id':'T1','tool_version':'1.5'});writej(ic/'provider_evidence_gap_microsoft.json',gap);writej(ic/'service_slo.json',slo);writej(ic/'production_readiness_v15.json',rd)
    cp=subprocess.run([sys.executable,str(HERE/'enterprise_v15_analyze.py'),'--case',str(ic)],capture_output=True,text=True);assert cp.returncode==0,(cp.stdout,cp.stderr)
    profile=json.loads((ic/'incident_profile.json').read_text());assert 'enterprise.provider_collection_gap' in profile.get('additional_evidence_pack_ids',[])
    fc=full_case(ic);assert fc['enterprise_v15']['provider_gaps'] and fc['enterprise_v15']['presence']['production_readiness'];r['enterprise_case_and_pack_integration']='PASS'

    # Case initializer.
    initroot=out/'init';cp=subprocess.run([sys.executable,str(HERE/'case_init.py'),'--case-id','V15','--root',str(initroot)],capture_output=True,text=True);assert cp.returncode==0
    meta=json.loads((initroot/'V15/00_case/case.json').read_text());assert meta['tool_version']=='1.5' and (initroot/'V15/37_service_health').is_dir();r['v15_case_initializer']='PASS'

    # Dashboard version/read-only integration.
    dash=(HERE/'analyst_dashboard.py').read_text();assert 'Distributed Enterprise Trust & Provider Collection' in dash and "version':'1.5" in dash and 'def do_POST(self):self.send_json(405' in dash;r['workbench_v15_integration']='PASS'

    final={'status':'PASS','evidence_pack_count':len(packs),'components':r};writej(out/'V1.5_SELFTEST.json',final);print(json.dumps(final,indent=2,sort_keys=True))

if __name__=='__main__':main()
