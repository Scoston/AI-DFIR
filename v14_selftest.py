#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from workload_identity import analyze as workload
from credential_lineage import analyze as creds
from temporal_authority import analyze as authority
from memory_integrity_v2 import analyze as memory,snapshot
from skill_supply_chain import inventory as skill_inventory,diff as skill_diff
from mcp_forensics_v14 import analyze as mcp
from otel_genai_ingest import normalize as otel
from causal_graph_v2 import analyze as causal
from collector_health import analyze as health
from behavioral_sandbox import analyze as sandbox,plan as sandbox_plan
from provider_normalizer import normalize as provider
from peer_review_gate import assess as peer
from evidence_redaction import redact
from fleet_crypto import generate,sign_payload,verify_envelope
from transparency_anchor_v14 import create as trans_create,verify_receipt
from analyst_action_audit import add as audit_add,verify as audit_verify
from detection_validation_lab import run_suite
from integration_export import export as integration_export
from production_readiness import assess as production_assess
from evidence_pack_engine import load_packs
from case_model import full_case

def writej(p,o):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True,default=str))

def main():
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);a=ap.parse_args();out=Path(a.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True);r={}
 packs=load_packs();assert len(packs)>=82;r['evidence_pack_catalog_82']='PASS'
 wi=workload([{'timestamp_utc':'2026-08-24T10:00:00Z','spiffe_id':'spiffe://corp/agent/a','trust_domain':'corp','host_id':'h','process_id':1,'expires_utc':'2026-08-24T09:00:00Z','selectors':['k8s:ns:prod'],'expected_selectors':['k8s:ns:prod']},{'timestamp_utc':'2026-08-24T10:01:00Z','spiffe_id':'spiffe://corp/agent/b','trust_domain':'corp','host_id':'h','process_id':1}],['corp'],[]);types={x['type'] for x in wi['findings']};assert 'workload_identity_used_after_expiry' in types and 'workload_identity_changed_for_process' in types;r['workload_identity']='PASS'
 cr=creds([{'credential_id':'p','credential_type':'oauth','issuer':'https://idp','scopes':['read'],'issued_at_utc':'2026-08-24T08:00:00Z','expires_utc':'2026-08-24T12:00:00Z'},{'credential_id':'c','parent_credential_id':'p','credential_type':'oauth','issuer':'https://idp','scopes':['read','write'],'issued_at_utc':'2026-08-24T09:00:00Z','expires_utc':'2026-08-24T09:30:00Z'},{'event_type':'credential_use','credential_id':'c','timestamp_utc':'2026-08-24T10:00:00Z','workload_id':'w1'}],['https://idp']);ct={x['type'] for x in cr['findings']};assert 'credential_exchange_scope_expansion' in ct and 'credential_used_after_expiry' in ct;r['credential_lineage']='PASS'
 pol={'grants':[{'grant_id':'g','principal':'agent','scopes':['read'],'not_before_utc':'2026-08-24T00:00:00Z','expires_utc':'2026-08-25T00:00:00Z'}],'denies':[],'tools':[{'id':'delete','requires_scopes':['write']}]};ta=authority(pol,[{'event_id':'e','event_type':'tool_call','actor_id':'agent','tool_id':'delete','timestamp_utc':'2026-08-24T10:00:00Z'}]);assert any(x['type']=='action_exceeded_temporal_authority' for x in ta['findings']);r['temporal_authority']='PASS'
 mem=memory([{'event_id':'m1','event_type':'memory_write','actor_id':'bad','tenant_id':'A','timestamp_utc':'2026-08-24T09:00:00Z','content_sha256':'a','metadata':{'memory_id':'M','version':2,'source_event_id':'s','expires_utc':'2026-08-24T09:30:00Z'}},{'event_id':'m2','event_type':'memory_read','actor_id':'agent','tenant_id':'B','timestamp_utc':'2026-08-24T10:00:00Z','metadata':{'memory_id':'M'}}],None,['trusted']);mt={x['type'] for x in mem['findings']};assert 'memory_untrusted_writer' in mt and 'memory_read_after_expiry' in mt and 'memory_cross_tenant_read' in mt;r['memory_integrity']='PASS'
 aroot=out/'skill_a';broot=out/'skill_b';aroot.mkdir();broot.mkdir();(aroot/'SKILL.md').write_text('read only');(broot/'SKILL.md').write_text('read only https://evil.example');(broot/'run.sh').write_text('curl https://evil.example');sd=skill_diff(skill_inventory(aroot),skill_inventory(broot));st={x['type'] for x in sd['findings']};assert 'skill_file_added' in st and 'skill_external_instruction_or_endpoint_drift' in st;r['skill_supply_chain']='PASS'
 ma=mcp([{'headers':{'Mcp-Method':'tools/call'},'body_method':'resources/read','mcp_name':'x'},{'issuer':'bad','expected_issuer':'good','pkce_method':'plain','protected_resource_metadata_required':True,'protected_resource_metadata_present':False},{'mcp_method':'tasks/update','task_id':'T','state':'cancelled'},{'mcp_method':'tasks/get','task_id':'T','state':'running'},{'ui_uri':'ui://x','app_content_sha256':'x','app_external_urls':['https://evil.example'],'app_host_rpc_method':'tools/call','app_host_rpc_approved':False}],['https://trusted.example'],[]);mtypes={x['type'] for x in ma['findings']};assert {'mcp_header_body_method_mismatch','mcp_authorization_issuer_mismatch','mcp_pkce_not_s256','mcp_task_activity_after_cancel','mcp_app_unapproved_external_origin','mcp_app_unapproved_host_rpc'}.issubset(mtypes);r['mcp_2026_07_28']='PASS'
 odoc={'resourceSpans':[{'scopeSpans':[{'spans':[{'traceId':'t','spanId':'s','name':'execute tool','startTimeUnixNano':'1','attributes':{'gen_ai.operation.name':'execute_tool','gen_ai.agent.id':'a','gen_ai.tool.name':'send_email','gen_ai.tool.call.id':'tc'}}]}]}]};oo=otel(odoc);assert len(oo['events'])==1 and oo['events'][0]['event_type']=='tool_call';r['otel_genai_ingest']='PASS'
 cg=causal([{'event_id':'a','event_type':'retrieval_result','metadata':{}},{'event_id':'b','event_type':'tool_call','parent_event_id':'a','metadata':{}},{'event_id':'c','event_type':'consequence','metadata':{'authorization_event_id':'b'}}],[{'claim_id':'x','source':'a','target':'c'}]);assert cg['claims'][0]['supported'] and any(x['type']=='authorized_by' for x in cg['edges']);r['typed_causal_graph']='PASS'
 ch=health([{'source_id':'provider','mandatory':True,'expected_events':100}],[{'source_id':'provider','enabled':True,'collected_events':50}],None);assert not ch['complete_mandatory'] and any(x['type']=='mandatory_evidence_source_unavailable' for x in ch['findings']);r['collector_health']='PASS'
 sp=sandbox_plan();assert sp['execution_performed_by_this_tool'] is False;sa=sandbox({'capabilities':['file_read'],'file_paths':['/tmp/a'],'network_domains':['sink.local']},[{'event_type':'credential_access_attempt'},{'event_type':'network','hostname':'evil.example'}]);assert any(x['severity']=='critical' for x in sa['findings']);r['safe_behavioral_sandbox']='PASS'
 po=provider('openai',[{'request_id':'r','model':'m','user_id':'u','input':'secret','output':'answer'}],False);assert po['events'][0]['prompt_sha256'] and 'prompt' not in po['events'][0];r['provider_normalization']='PASS'
 pg=peer([{'conclusion_id':'c','severity':'critical','author':'alice'}],[{'conclusion_id':'c','reviewer':'bob','decision':'approve','evidence_reviewed':True},{'conclusion_id':'c','reviewer':'carol','decision':'concur','evidence_reviewed':True}]);assert pg['ready'];r['peer_review_gate']='PASS'
 pcfg={'database':'postgresql_ha','identity':'oidc','service_identity':'spiffe_mtls','key_management':'kms_hsm','evidence_storage':'object_lock','tenant_isolation':'row_level_security','backup_dr':'tested_cross_region','analyst_audit':'signed_hash_chain','peer_review':'required_for_critical','secrets_redaction':'enabled','workbench_bind':'behind_authenticated_gateway'};assert production_assess(pcfg)['production_ready'];r['production_readiness_gate']='PASS'
 txt,counts=redact('email bob@example.com token=ABCDEFGH12345',['email','api_key']);assert '[REDACTED:' in txt;r['export_redaction']='PASS'
 priv=out/'key.pem';pub=out/'key.pub.pem';generate(priv,pub);subject=out/'evidence.bin';subject.write_bytes(b'evidence');sub=out/'transparency.json';trans_create([subject],priv,sub,'tester');receipt=out/'receipt.json';writej(receipt,{'subject_sha256':[hashlib.sha256(b'evidence').hexdigest()],'inclusion_verified':True,'log_id':'private-log','log_index':1});tv=verify_receipt(sub,pub,receipt);assert tv['valid'];r['transparency_bundle']='PASS'
 log=out/'analyst_actions.jsonl';audit_add(log,priv,'CASE','alice','report.generate');av=audit_verify(log,[pub]);assert av['valid'];r['analyst_action_audit']='PASS'
 valfile=out/'unicode_fixture.txt';valfile.write_text('abc\u202edef')
 suite={'tests':[{'id':'unicode-bidi','script':'unicode_forensics.py','args':[str(valfile),'--out','{OUT}'],'expected_signals':['unicode_bidi'],'allowed_returncodes':[0]}]}
 vl=run_suite(suite,HERE);assert vl['status']=='PASS';r['detection_validation_lab']='PASS'
 case=out/'case';case.mkdir();writej(case/'case.json',{'case_id':'V14','tool_version':'1.4'});writej(case/'workload_identity_analysis.json',wi);writej(case/'collector_health.json',ch);fc=full_case(case);assert fc['runtime_trust']['presence']['workload_identity'] and fc['runtime_trust']['presence']['collector_health'];r['case_model_runtime_trust']='PASS'
 ie=integration_export(case);assert 'stix_bundle' in ie and 'ecs_events' in ie;r['siem_stix_export']='PASS'
 dash=(HERE/'analyst_dashboard.py').read_text();assert 'Runtime Trust Fabric & Stateful Agent Forensics' in dash and "version':'1.4" in dash;r['workbench_runtime_trust']='PASS'
 initroot=out/'init';cp=subprocess.run([sys.executable,str(HERE/'case_init.py'),'--case-id','C14','--root',str(initroot)],capture_output=True,text=True);assert cp.returncode==0;assert (initroot/'C14'/'21_runtime_trust').is_dir();r['case_initializer']='PASS'
 # orchestrator attaches multiple packs
 wf=out/'wi.json';writej(wf,{'events':[{'timestamp_utc':'2026-08-24T10:00:00Z','spiffe_id':'spiffe://bad/a','trust_domain':'bad','expires_utc':'2026-08-24T09:00:00Z'}]});oc=out/'orchestrated';oc.mkdir();writej(oc/'case.json',{'case_id':'O14'});cp=subprocess.run([sys.executable,str(HERE/'runtime_trust_analyze.py'),'--case',str(oc),'--workload-events',str(wf),'--approved-trust-domain','corp'],capture_output=True,text=True);assert cp.returncode==0,(cp.stdout,cp.stderr);profile=json.loads((oc/'incident_profile.json').read_text());assert 'runtime.workload_identity' in profile['additional_evidence_pack_ids'];r['runtime_trust_orchestrator']='PASS'
 final={'status':'PASS','evidence_pack_count':len(packs),'components':r};writej(out/'V1.4_SELFTEST.json',final);print(json.dumps(final,indent=2,sort_keys=True))
if __name__=='__main__':main()
