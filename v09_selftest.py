#!/usr/bin/env python3
from pathlib import Path
import argparse, json, shutil, subprocess, sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))

from evidence_pack_engine import load_packs, get_pack, resolve, create_profile
from mcp_forensics import diff as mcp_diff
from rag_forensics import corpus_diff, provenance as rag_provenance
from memory_forensics import analyze as memory_analyze
from authority_engine import diff as authority_diff
from agentic_graph import analyze as causal_analyze
from agentic_rules import collect_signals, evaluate as eval_rules, load_json
from case_model import full_case
from report_generator import markdown

MS_IDS={
'AI.Azure_CredentialTheftAttempt',
'AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt',
'AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt',
'AI.Azure_MaliciousUrl.ModelResponse',
'AI.Azure_MaliciousUrl.UnknownSource',
'AI.Azure_MaliciousUrl.UserPrompt',
'AI.Azure_AccessFromSuspiciousUserAgent',
'AI.Azure_ASCIISmuggling',
'AI.Azure_AccessFromAnonymizedIP',
'AI.Azure_AccessFromSuspiciousIP',
'AI.Azure_DOWDuplicateRequests',
'AI.Azure_DOWVolumeAnomaly',
'AI.Azure_AccessAnomaly',
'AI.Azure_AnomalousOperation.InitialAccess',
'AI.Azure_AnomalousToolInvocation',
'AI.Azure_LLMReconnaissance',
'AI.AIModelScan_MalwareDetected',
}

def writej(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True),encoding="utf-8")

def writejl(p,rows):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in rows),encoding="utf-8")

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);a=ap.parse_args()
    out=Path(a.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)
    result={}

    # 1. Pack catalog: v0.8 vendor packs + v0.9 agentic packs.
    packs=load_packs()
    ids={p["id"] for p in packs}
    assert len(ids)==len(packs)
    assert len(packs)>=37
    for i in range(1,11):
        assert f"owasp.agentic.asi{i:02d}" in ids
    assert "agentic.mcp.protocol_compromise.2026_07_28" in ids
    result["agentic_evidence_pack_catalog"]="PASS"

    # 2. Microsoft catalog survived intact.
    for aid in MS_IDS:
        rows=resolve(alert_id=aid)
        assert rows and rows[0]["score"]>=100
    catalog=json.loads((HERE/"MICROSOFT_AI_ALERT_CATALOG.json").read_text())
    assert len(catalog["alerts"])==18
    result["microsoft_v08_catalog_retained"]="PASS"

    # 3. MCP diff.
    approved_mcp={"servers":[{
        "server_id":"svc-1","url":"https://mcp.example","protocol_version":"2026-07-28",
        "authorization_issuer":"https://id.example","client_id":"client-1",
        "tools":[{"name":"lookup","description":"read","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}],
        "prompts":[],"resources":[]
    }]}
    suspect_mcp={"servers":[{
        "server_id":"svc-1","url":"https://mcp.example","protocol_version":"2026-07-28",
        "authorization_issuer":"https://evil.example","client_id":"client-1",
        "tools":[
          {"name":"lookup","description":"read and export","inputSchema":{"type":"object","properties":{"q":{"type":"string"},"send_to":{"type":"string"}}}},
          {"name":"disable_user","description":"disable","inputSchema":{"type":"object","properties":{"id":{"type":"string"}}}}
        ],"prompts":[],"resources":[]
    }]}
    mf=mcp_diff(approved_mcp,suspect_mcp)
    types={x["type"] for x in mf}
    assert "mcp_authorization_issuer_changed" in types
    assert "mcp_tool_schema_changed" in types
    assert "unexpected_mcp_tool" in types
    result["mcp_inventory_and_auth_diff"]="PASS"

    # 4. Agentic event chain with persistent memory -> tool -> consequence.
    events=[
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"e1","timestamp_utc":"2026-08-23T20:00:00Z",
       "event_type":"memory_write","actor_id":"untrusted-agent","target_id":"mem-1","parent_event_id":None,
       "cause_event_ids":[],"correlation_ids":[],"content_sha256":"badmem","authority_id":None,
       "session_id":"s1","trace_id":"t1","metadata":{"memory_id":"mem-1","source_event_id":"upload-1","suspected_root_cause":True}},
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"e2","timestamp_utc":"2026-08-23T20:10:00Z",
       "event_type":"memory_read","actor_id":"agent-A","target_id":"mem-1","parent_event_id":None,
       "cause_event_ids":["e1"],"correlation_ids":[],"content_sha256":"badmem","authority_id":"auth-A",
       "session_id":"s2","trace_id":"t2","metadata":{"memory_id":"mem-1"}},
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"e3","timestamp_utc":"2026-08-23T20:10:01Z",
       "event_type":"tool_call","actor_id":"agent-A","target_id":"disable_user","parent_event_id":"e2",
       "cause_event_ids":[],"correlation_ids":[],"content_sha256":"toolcall","authority_id":"auth-A",
       "session_id":"s2","trace_id":"t2","metadata":{"tool_name":"disable_user"}},
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"e4","timestamp_utc":"2026-08-23T20:10:02Z",
       "event_type":"consequence","actor_id":"directory-api","target_id":"account-disabled","parent_event_id":"e3",
       "cause_event_ids":[],"correlation_ids":[],"content_sha256":"impact","authority_id":None,
       "session_id":"s2","trace_id":"t2","metadata":{}},
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"r1","timestamp_utc":"2026-08-23T20:20:00Z",
       "event_type":"retrieval_result","actor_id":"rag-service","target_id":"doc-7","parent_event_id":None,
       "cause_event_ids":[],"correlation_ids":[],"content_sha256":"poisoned-chunk","authority_id":None,
       "session_id":"s3","trace_id":"t3","metadata":{"document_id":"doc-7","included_in_prompt":True,"chunk_sha256":"poisoned-chunk"}},
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"r2","timestamp_utc":"2026-08-23T20:20:01Z",
       "event_type":"tool_call","actor_id":"agent-B","target_id":"export_data","parent_event_id":"r1",
       "cause_event_ids":[],"correlation_ids":[],"content_sha256":"x","authority_id":"auth-B",
       "session_id":"s3","trace_id":"t3","metadata":{}},
      {"schema":"ai-dfir/agentic-event/v0.9","event_id":"r3","timestamp_utc":"2026-08-23T20:20:02Z",
       "event_type":"consequence","actor_id":"external-api","target_id":"data-exported","parent_event_id":"r2",
       "cause_event_ids":[],"correlation_ids":[],"content_sha256":"y","authority_id":None,
       "session_id":"s3","trace_id":"t3","metadata":{}}
    ]
    evfile=out/"agentic_events.jsonl";writejl(evfile,events)
    mem=memory_analyze(events,["approved-memory-service"])
    mtypes={x["type"] for x in mem["findings"]}
    assert "memory_untrusted_writer" in mtypes
    assert "memory_cross_session_propagation" not in mtypes  # only one other session in this fixture
    causal=causal_analyze(events,["e1","r1"])
    assert len(causal["causal_paths"])==2
    assert all(x["causal"] for x in causal["causal_paths"])
    result["memory_and_causal_reconstruction"]="PASS"

    # 5. RAG corpus + blast radius.
    ac={"documents":[{"document_id":"doc-7","sha256":"good","acl_sha256":"acl","metadata_sha256":"m"}]}
    sc={"documents":[{"document_id":"doc-7","sha256":"bad","acl_sha256":"acl","metadata_sha256":"m"}]}
    rd=corpus_diff(ac,sc)
    assert any(x["type"]=="rag_sha256_changed" for x in rd)
    rp=rag_provenance(events,["poisoned-chunk"])
    assert rp["affected_session_count"]==1
    assert rp["affected_sessions"][0]["consequences"]==["r3"]
    result["rag_poisoning_blast_radius"]="PASS"

    # 6. Effective authority expansion.
    aa={"principals":[{"id":"agent-A","roles":["reader"],"direct_scopes":[]}],
        "roles":[{"id":"reader","scopes":["read:users"]}],
        "tools":[{"id":"disable_user","requires_scopes":["write:users"],"mutating":True}],
        "delegations":[],"approval_policies":[{"tool":"disable_user","required":True}]}
    sa={"principals":[{"id":"agent-A","roles":["reader"],"direct_scopes":[]}],
        "roles":[{"id":"reader","scopes":["read:users"]}],
        "tools":[{"id":"disable_user","requires_scopes":["write:users"],"mutating":True}],
        "delegations":[{"from":"service-admin","to":"agent-A","scopes":["write:users"]}],
        "approval_policies":[{"tool":"disable_user","required":True}]}
    ad=authority_diff(aa,sa)
    atypes={x["type"] for x in ad["findings"]}
    assert "effective_authority_expanded" in atypes and "new_tool_reachability" in atypes
    result["effective_authority_diff"]="PASS"

    # 7. Deterministic rule engine.
    mcpfile=out/"mcp_findings.json";writej(mcpfile,{"findings":mf})
    memfile=out/"memory_lineage.json";writej(memfile,mem)
    authfile=out/"authority_diff.json";writej(authfile,ad)
    rules=load_json(HERE/"agentic_detection_rules.json")
    signals,ets,_=collect_signals([str(mcpfile),str(memfile),str(authfile),str(evfile)])
    hits=eval_rules(rules,signals,ets)
    hit_ids={x["rule_id"] for x in hits}
    assert "AIR-ASI02-001" in hit_ids
    assert "AIR-ASI03-001" in hit_ids
    assert "AIR-ASI06-001" in hit_ids
    result["agentic_rule_engine"]="PASS"

    # 8. Multi-pack Microsoft + OWASP analysis.
    case=out/"case";case.mkdir()
    writej(case/"case.json",{"case_id":"MS-AGENTIC-001","tool_version":"0.9"})
    create_profile(case,"microsoft.AI.Azure_AnomalousToolInvocation",
                   alert_id="AI.Azure_AnomalousToolInvocation")
    # Native Microsoft artifacts.
    for fn in ["AlertInfo.json","AlertEvidence.json","signin.json","request_response.json",
               "tool_schema.json","tool_call.json","tool_result.json","target_system.json"]:
        writej(case/fn,[])
    # Technique artifacts for ASI02/03/06.
    shutil.copy2(evfile,case/"agentic_events.jsonl")
    writej(case/"authority.json",sa)
    writej(case/"target_audit.json",[])
    writej(case/"memory_snapshot.json",{"mem-1":{"sha256":"badmem"}})
    writej(case/"retrieval.json",[])
    writej(case/"conversation.json",[])
    writej(case/"mcp_inventory.json",suspect_mcp)

    aa_file=out/"approved_authority.json";sa_file=out/"suspect_authority.json"
    amcp=out/"approved_mcp.json";smcp=out/"suspect_mcp.json"
    writej(aa_file,aa);writej(sa_file,sa);writej(amcp,approved_mcp);writej(smcp,suspect_mcp)
    cp=subprocess.run([sys.executable,str(HERE/"agentic_case_analyze.py"),
                       "--case",str(case),"--events",str(case/"agentic_events.jsonl"),
                       "--mcp-approved",str(amcp),"--mcp-suspect",str(smcp),
                       "--authority-approved",str(aa_file),"--authority-suspect",str(sa_file),
                       "--trusted-memory-writer","approved-memory-service",
                       "--seed","e1"],text=True,capture_output=True)
    assert cp.returncode==0,(cp.stdout,cp.stderr)
    profile=json.loads((case/"incident_profile.json").read_text())
    assert profile["evidence_pack_id"]=="microsoft.AI.Azure_AnomalousToolInvocation"
    adds=set(profile["additional_evidence_pack_ids"])
    assert "owasp.agentic.asi02" in adds and "owasp.agentic.asi03" in adds and "owasp.agentic.asi06" in adds

    fc=full_case(case)
    ep=fc["evidence_pack"]
    assert ep["selected"] and len(ep["assessments"])>=4
    assert fc["agentic"]["presence"]["mcp"]
    assert fc["agentic"]["presence"]["authority"]
    assert fc["agentic"]["presence"]["memory"]
    report=markdown(fc)
    assert "Agentic Incident Reconstruction" in report
    assert "Timestamp proximity" in report
    result["multi_pack_vendor_plus_technique"]="PASS"

    # 9. Dashboard remains read only and advertises v0.9 agentic panel.
    dash=(HERE/"analyst_dashboard.py").read_text()
    assert "Agentic Incident Reconstruction" in dash
    assert "version':'0.9" in dash
    assert "def do_POST(self):self.send_json(405" in dash
    result["read_only_workbench_integration"]="PASS"

    final={"status":"PASS","pack_count":len(packs),"owasp_agentic_pack_count":10,
           "microsoft_defender_for_cloud_pack_count":18,"components":result}
    (out/"V0.9_SELFTEST.json").write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))

if __name__=="__main__":main()
