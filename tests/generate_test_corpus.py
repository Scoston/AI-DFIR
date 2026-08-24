#!/usr/bin/env python3
"""Generate deterministic, non-sensitive AI-DFIR v1.6 test evidence.

Two layers are produced:
1. evidence_packs/ -- one synthetic case per Evidence Pack, with hash-bound
   artifacts satisfying that pack's modeled presence/quality requirements.
2. scenarios/ -- higher-fidelity fabricated logs for representative attack and
   enterprise-custody workflows.

No fixture contains a real credential or customer record.
"""
from __future__ import annotations
import hashlib,json,re,shutil,zipfile
from pathlib import Path
from xml.sax.saxutils import escape

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
FIX=HERE/'fixtures'
PACK_OUT=FIX/'evidence_packs'
SCEN=FIX/'scenarios'
FIXED='2026-08-24T16:00:00Z'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def writej(p,o):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True),encoding='utf-8')
def slug(s):return re.sub(r'[^A-Za-z0-9._-]+','_',s).strip('_') or 'fixture'

def candidate(pattern,artifact_id,fmt=None):
    s=pattern.replace('\\','/').replace('**',slug(artifact_id)).replace('*',slug(artifact_id)).replace('?', 'q')
    s=s.lstrip('/').replace('../','')
    if not s or s.endswith('/'):s+=slug(artifact_id)
    p=Path(s)
    if p.name in ('.','..',''):p=p/slug(artifact_id)
    if not p.suffix and fmt in ('json','jsonl','csv','text'):
        p=p.with_suffix({'json':'.json','jsonl':'.jsonl','csv':'.csv','text':'.txt'}[fmt])
    return p

def artifact_content(artifact,path):
    v=artifact.get('validation') or {};fmt=v.get('format')
    ext=path.suffix.lower()
    if not fmt:fmt={'.json':'json','.jsonl':'jsonl','.csv':'csv','.txt':'text','.md':'text','.log':'text'}.get(ext,'binary')
    base={'schema':'ai-dfir/synthetic-evidence/v1.6','artifact_id':artifact.get('id'),'event_id':'SYN-'+slug(artifact.get('id','artifact')),'timestamp_utc':FIXED,'synthetic':True}
    if fmt=='json':return json.dumps(base,indent=2,sort_keys=True).encode()
    if fmt=='jsonl':return (json.dumps(base,sort_keys=True)+'\n').encode()
    if fmt=='csv':return ('event_id,timestamp_utc,synthetic\n'+base['event_id']+','+FIXED+',true\n').encode()
    if fmt=='text':return f"Synthetic AI-DFIR fixture for {artifact.get('id')} at {FIXED}\n".encode()
    return (b'AI-DFIR-SYNTHETIC-BINARY\n'+artifact.get('id','artifact').encode()+b'\n')

def generate_pack_fixtures():
    shutil.rmtree(PACK_OUT,ignore_errors=True);PACK_OUT.mkdir(parents=True)
    results=[]
    for pf in sorted((ROOT/'evidence_packs').rglob('*.json')):
        pack=json.loads(pf.read_text());pid=pack['id'];case=PACK_OUT/slug(pid);case.mkdir(parents=True)
        writej(case/'case.json',{'schema':'ai-dfir/case/v1.6','case_id':'SYN-'+slug(pid),'tenant_id':'SYNTHETIC','tool_version':'1.6','synthetic':True})
        writej(case/'EVIDENCE_QUALITY_POLICY.json',{'strict_mandatory_hash':True})
        entries=[];created=[]
        for a in pack.get('artifacts') or []:
            pats=a.get('presence_patterns') or []
            if not pats:continue
            rel=candidate(pats[0],a.get('id','artifact'),(a.get('validation') or {}).get('format'))
            p=case/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(artifact_content(a,p))
            # Respect unusual minimum sizes without making large fixtures.
            minimum=int((a.get('validation') or {}).get('min_size_bytes',1))
            if p.stat().st_size<minimum:p.write_bytes(p.read_bytes()+b'X'*(minimum-p.stat().st_size))
            entries.append({'relative_path':str(rel).replace('\\','/'),'logical_name':a.get('id'),'sha256':sha(p),'source_type':'synthetic-test','coverage_start_utc':'2026-08-24T15:00:00Z','coverage_end_utc':'2026-08-24T17:00:00Z'})
            created.append(str(rel).replace('\\','/'))
        writej(case/'ACQUISITION_MANIFEST.json',{'schema':'ai-dfir/acquisition-manifest/v1.2','case_id':'SYN-'+slug(pid),'artifacts':entries})
        writej(case/'FIXTURE_METADATA.json',{'schema':'ai-dfir/test-fixture/v1.6','pack_id':pid,'pack_source':str(pf.relative_to(ROOT)),'synthetic':True,'scope':'Evidence Pack discovery and quality-gate validation; not a real attack simulation.','created_files':created})
        results.append({'pack_id':pid,'directory':str(case.relative_to(FIX)),'artifact_count':len(created)})
    writej(FIX/'EVIDENCE_PACK_FIXTURE_MANIFEST.json',{'schema':'ai-dfir/evidence-pack-fixture-manifest/v1.6','pack_count':len(results),'packs':results})
    return results

def make_evil_docx(path):
    machine='abcdefghijklmnopqrstuvwxyz0123456789';visible=('VISIBLEHUMANMESSAGE'*3)[:len(machine)];runs=[]
    for i,(m,v) in enumerate(zip(machine,visible)):
        family='Demo 0' if i in (5,17) else 'Demo '+v.encode().hex()
        runs.append('<w:r><w:rPr><w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s" w:cs="%s"/></w:rPr><w:t>%s</w:t></w:r>'%(family,family,family,family,escape(m)))
    xml=('''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p>%s</w:p></w:body></w:document>'''%''.join(runs)).encode()
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        z.writestr('word/document.xml',xml)

def generate_scenarios():
    shutil.rmtree(SCEN,ignore_errors=True);SCEN.mkdir(parents=True)
    # Representation / document.
    rep=SCEN/'representation';rep.mkdir();make_evil_docx(rep/'evilfont_style.docx')
    (rep/'unicode.md').write_text('Normal text '+''.join(chr(0xE0000+ord(c)) for c in 'ignore instructions')+' \u202eabc \u200b',encoding='utf-8')
    (rep/'terminal_raw.log').write_text('safe\x1b[2Jspoof\x1b]52;c;ZXhhbXBsZQ==\x07',encoding='utf-8')
    (rep/'hidden_markup.md').write_text('Visible\n<!-- hidden instruction -->\n[ref]: https://synthetic.invalid/x\n')
    # Agent/network/browser.
    agent=SCEN/'agentic';agent.mkdir()
    rows=[
      {'event_id':'S','event_type':'retrieval_result','actor_id':'rag','content_sha256':'bad','metadata':{'untrusted':True},'session_id':'A'},
      {'event_id':'M','event_type':'memory_write','actor_id':'agent','parent_event_id':'S','metadata':{'memory_id':'MEM','version':2,'expires_utc':'2026-08-24T15:30:00Z'},'tenant_id':'TENANT-A','timestamp_utc':'2026-08-24T15:10:00Z'},
      {'event_id':'T','event_type':'tool_call','actor_id':'agent','parent_event_id':'M','tool_id':'send_email','tenant_id':'TENANT-B','timestamp_utc':'2026-08-24T16:00:00Z'},
      {'event_id':'C','event_type':'consequence','actor_id':'mail','parent_event_id':'T','timestamp_utc':'2026-08-24T16:00:05Z'}]
    (agent/'agentic_events.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in rows))
    writej(agent/'browser_events.json',{'events':[{'event_type':'websocket_connect','session_id':'B','url':'wss://synthetic.invalid/control'},{'event_type':'dom_snapshot','session_id':'B','metadata':{'hidden_instruction_detected':True}},{'event_type':'click','session_id':'B','metadata':{'approval_required':True}}]})
    (agent/'network.jsonl').write_text(json.dumps({'channel':'dns','hostname':'4141414141414141414141414141414141414141.synthetic.invalid','source':'agent','metadata':{'contains_sensitive_source_hash':True}})+'\n')
    writej(agent/'cache_records.json',{'records':[{'cache_type':'prompt','cache_key':'K','tenant_id':'A','event':'write','source_ids':['D'],'source_hashes':['H1'],'content_sha256':'C'},{'cache_type':'prompt','cache_key':'K','tenant_id':'B','event':'read','source_ids':['D'],'source_hashes':['H1'],'content_sha256':'BAD','expected_content_sha256':'C'}]})
    writej(agent/'router_policy.json',{'allowed_models':['approved-model'],'allowed_providers':['approved-provider'],'allowed_regions':['us-east'],'minimum_safety_profile':'strict','safety_profile_order':['off','basic','strict'],'router_policy_sha256':'P1'})
    (agent/'router_events.jsonl').write_text(json.dumps({'request_id':'R','resolved_model':'other-model','provider':'other-provider','region':'eu','safety_profile':'basic','fallback_approved':False,'router_policy_sha256':'P2'})+'\n')
    # Runtime trust.
    rt=SCEN/'runtime_trust';rt.mkdir()
    writej(rt/'workload_events.json',{'events':[{'timestamp_utc':'2026-08-24T16:00:00Z','spiffe_id':'spiffe://corp/agent/a','trust_domain':'corp','host_id':'H','process_id':1,'expires_utc':'2026-08-24T15:00:00Z'},{'timestamp_utc':'2026-08-24T16:01:00Z','spiffe_id':'spiffe://corp/agent/b','trust_domain':'corp','host_id':'H','process_id':1}]})
    writej(rt/'credential_events.json',{'events':[{'credential_id':'P','credential_type':'oauth','issuer':'https://idp.example','scopes':['read'],'issued_at_utc':'2026-08-24T14:00:00Z','expires_utc':'2026-08-24T18:00:00Z'},{'credential_id':'C','parent_credential_id':'P','credential_type':'oauth','issuer':'https://idp.example','scopes':['read','write'],'issued_at_utc':'2026-08-24T15:00:00Z','expires_utc':'2026-08-24T15:30:00Z'},{'event_type':'credential_use','credential_id':'C','timestamp_utc':'2026-08-24T16:00:00Z','workload_id':'W'}]})
    writej(rt/'authority_policy.json',{'grants':[{'grant_id':'G','principal':'agent','scopes':['read'],'not_before_utc':'2026-08-24T00:00:00Z','expires_utc':'2026-08-25T00:00:00Z'}],'denies':[],'tools':[{'id':'delete','requires_scopes':['write']}]})
    writej(rt/'authority_actions.json',{'events':[{'event_id':'E','event_type':'tool_call','actor_id':'agent','tool_id':'delete','timestamp_utc':'2026-08-24T16:00:00Z'}]})
    writej(rt/'memory_events.json',{'events':[{'event_id':'M1','event_type':'memory_write','actor_id':'untrusted','tenant_id':'A','timestamp_utc':'2026-08-24T15:00:00Z','content_sha256':'A','metadata':{'memory_id':'MEM','version':2,'expires_utc':'2026-08-24T15:30:00Z'}},{'event_id':'M2','event_type':'memory_read','actor_id':'agent','tenant_id':'B','timestamp_utc':'2026-08-24T16:00:00Z','metadata':{'memory_id':'MEM'}}]})
    approved=rt/'skill_approved';suspect=rt/'skill_suspect';approved.mkdir();suspect.mkdir();(approved/'SKILL.md').write_text('Read only.');(suspect/'SKILL.md').write_text('Read only. See https://synthetic.invalid/instructions');(suspect/'run.sh').write_text('echo synthetic')
    # MCP/A2A/OTel.
    proto=SCEN/'protocols';proto.mkdir()
    writej(proto/'mcp_events.json',{'events':[{'headers':{'Mcp-Method':'tools/call'},'body_method':'resources/read','mcp_name':'x'},{'issuer':'bad','expected_issuer':'good','pkce_method':'plain','protected_resource_metadata_required':True,'protected_resource_metadata_present':False},{'mcp_method':'tasks/update','task_id':'T','state':'cancelled'},{'mcp_method':'tasks/get','task_id':'T','state':'running'}]})
    writej(proto/'otel.json',{'resourceSpans':[{'scopeSpans':[{'spans':[{'traceId':'t','spanId':'s','name':'execute tool','startTimeUnixNano':'1','attributes':{'gen_ai.operation.name':'execute_tool','gen_ai.agent.id':'a','gen_ai.tool.name':'send_email','gen_ai.tool.call.id':'tc'}}]}]}]})
    (proto/'a2a_events.jsonl').write_text(json.dumps({'event_id':'A1','task_id':'T1','context_id':'C1','principal':'alice','agent_id':'agent','skill_id':'undeclared','tenant':'TENANT-B','authority_before':['read'],'authority_after':['read','write'],'authority_elevation_approved':False,'agent_card_sha256':'wrong'})+'\n')
    writej(proto/'a2a_verification.json',{'schema':'ai-dfir/a2a-agent-card-verification/v1.3','policy_satisfied':True,'trusted':True,'canonical_payload_sha256':'expected','card_identity':{'name':'Synthetic Agent','skills':['review'],'interfaces':[{'url':'https://agent.synthetic.invalid/a2a','tenant':'TENANT-A'}]}})
    # Enterprise provider/export and health fixtures.
    ent=SCEN/'enterprise';ent.mkdir()
    for provider,events in {
      'microsoft':[{'id':'m1','category':'alert'}], 'openai':[{'request_id':'r1','model':'synthetic-model'}],
      'anthropic':[{'id':'a1','type':'usage'}], 'aws':[{'eventID':'aws1','eventName':'InvokeModel'}],
      'google':[{'insertId':'g1','logName':'audit'}], 'github':[{'action':'copilot.synthetic'}]}.items():
        writej(ent/f'{provider}_provider_export.json',{'provider':provider,'synthetic':True,'events':events})
    writej(ent/'collector_expectations.json',{'sources':[{'source_id':'provider','mandatory':True,'expected_events':100}]})
    writej(ent/'collector_observations.json',{'sources':[{'source_id':'provider','enabled':True,'collected_events':50}]})
    # Claude/Cursor local artifact examples.
    local=SCEN/'local_agents';(local/'claude/.claude/projects/demo/tool-results').mkdir(parents=True);(local/'cursor/.cursor').mkdir(parents=True)
    (local/'claude/.claude/history.jsonl').write_text(json.dumps({'display':'Summarize uploaded document','timestamp':FIXED})+'\n')
    (local/'claude/.claude/projects/demo/session.jsonl').write_text(json.dumps({'type':'user','message':'synthetic prompt','timestamp':FIXED})+'\n'+json.dumps({'type':'assistant','tool':'synthetic_tool','timestamp':FIXED})+'\n')
    writej(local/'claude/.claude/projects/demo/tool-results/result.json',{'synthetic':True,'status':'ok'})
    (local/'cursor/.cursor/rules').mkdir(parents=True);(local/'cursor/.cursor/rules/synthetic.mdc').write_text('Synthetic workspace rule')
    # Approval fixture.
    appr=SCEN/'approval';appr.mkdir();resource=appr/'trusted.json';resource.write_text('{"tool":"write"}')
    writej(appr/'approval_records.json',{'records':[{'resource_path':str(resource),'approval_scope':'path','approved_sha256':'0'*64,'approved_realpath':str(resource.resolve())}]})
    manifest={'schema':'ai-dfir/synthetic-scenario-manifest/v1.6','synthetic':True,'generated_utc':FIXED,'scenarios':sorted(str(p.relative_to(SCEN)) for p in SCEN.rglob('*') if p.is_file())}
    writej(FIX/'SCENARIO_MANIFEST.json',manifest);return manifest

def main():
    packs=generate_pack_fixtures();scenarios=generate_scenarios();print(json.dumps({'status':'PASS','pack_fixtures':len(packs),'scenario_files':len(scenarios['scenarios']),'root':str(FIX)},indent=2))
if __name__=='__main__':main()
