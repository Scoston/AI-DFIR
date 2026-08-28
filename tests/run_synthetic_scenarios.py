#!/usr/bin/env python3
"""Run high-fidelity, non-network synthetic detection scenarios."""
from __future__ import annotations
import json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(ROOT))
from generate_test_corpus import generate_scenarios
from evil_font_forensics import analyze_docx
from unicode_forensics import analyze as unicode_analyze
from terminal_render_forensics import analyze as terminal_analyze
from network_exfil_forensics import analyze as network_analyze,load as load_network
from browser_forensics import analyze as browser_analyze
from cache_forensics import analyze as cache_analyze
from router_forensics import analyze as router_analyze
from mcp_forensics_v14 import analyze as mcp_analyze
from otel_genai_ingest import normalize as otel_normalize
from memory_integrity_v2 import analyze as memory_analyze
from workload_identity import analyze as workload_analyze
from credential_lineage import analyze as credential_analyze
from temporal_authority import analyze as authority_analyze
from skill_supply_chain import inventory as skill_inventory,diff as skill_diff
from approval_integrity import analyze as approval_analyze
from causal_graph_v2 import analyze as causal_analyze
from collector_health import analyze as health_analyze
from a2a_execution_binding import analyze as a2a_bind,load_jsonl
from provider_normalizer import normalize as provider_normalize

def readj(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def types(o):return {x.get('type') for x in o.get('findings',[]) if isinstance(x,dict)}

def main():
    if not (HERE/'fixtures/SCENARIO_MANIFEST.json').exists():generate_scenarios()
    s=HERE/'fixtures/scenarios';r={}
    o=analyze_docx(s/'representation/evilfont_style.docx');assert 'machine_visible_text_disagreement_via_font_mapping' in types(o);r['evilfont_docx']='PASS'
    o=unicode_analyze((s/'representation/unicode.md').read_text(encoding='utf-8'));assert 'unicode_tag' in types(o) and 'unicode_bidi' in types(o);r['unicode']='PASS'
    o=terminal_analyze((s/'representation/terminal_raw.log').read_text(encoding='utf-8'));assert 'terminal_cursor_or_display_control' in types(o) and 'terminal_osc52_clipboard_control' in types(o);r['terminal']='PASS'
    o=network_analyze(load_network(s/'agentic/network.jsonl'),['corp.example']);assert 'dns_data_like_subdomain_label' in types(o);r['network_exfil']='PASS'
    b=readj(s/'agentic/browser_events.json')['events'];o=browser_analyze(b,approved_ws_origins=['wss://trusted.example']);assert 'browser_unapproved_websocket_origin' in types(o);r['browser']='PASS'
    c=readj(s/'agentic/cache_records.json')['records'];o=cache_analyze(c,{'D':'H2'});assert 'cross_tenant_cache_key_reuse' in types(o);r['cache']='PASS'
    pol=readj(s/'agentic/router_policy.json');events=[json.loads(x) for x in (s/'agentic/router_events.jsonl').read_text(encoding='utf-8').splitlines()];o=router_analyze(pol,events);assert 'unapproved_model_resolution' in types(o);r['router']='PASS'
    o=mcp_analyze(readj(s/'protocols/mcp_events.json')['events'],['https://trusted.example'],[]);assert 'mcp_header_body_method_mismatch' in types(o);r['mcp']='PASS'
    o=otel_normalize(readj(s/'protocols/otel.json'));assert o['events'] and o['events'][0]['event_type']=='tool_call';r['otel']='PASS'
    o=memory_analyze(readj(s/'runtime_trust/memory_events.json')['events'],None,['trusted']);assert 'memory_cross_tenant_read' in types(o);r['memory']='PASS'
    o=workload_analyze(readj(s/'runtime_trust/workload_events.json')['events'],['corp'],[]);assert 'workload_identity_used_after_expiry' in types(o);r['workload']='PASS'
    o=credential_analyze(readj(s/'runtime_trust/credential_events.json')['events'],['https://idp.example']);assert 'credential_exchange_scope_expansion' in types(o);r['credentials']='PASS'
    o=authority_analyze(readj(s/'runtime_trust/authority_policy.json'),readj(s/'runtime_trust/authority_actions.json')['events']);assert 'action_exceeded_temporal_authority' in types(o);r['authority']='PASS'
    o=skill_diff(skill_inventory(s/'runtime_trust/skill_approved'),skill_inventory(s/'runtime_trust/skill_suspect'));assert 'skill_file_added' in types(o);r['skills']='PASS'
    approval_records=readj(s/'approval/approval_records.json')['records']
    approval_resource=(s/'approval/trusted.json').resolve()
    for record in approval_records:
        record['resource_path']=str(approval_resource)
        record['approved_realpath']=str(approval_resource)
    o=approval_analyze(approval_records);assert 'approval_toctou_content_changed' in types(o);r['approval']='PASS'
    ev=[json.loads(x) for x in (s/'agentic/agentic_events.jsonl').read_text(encoding='utf-8').splitlines()];o=causal_analyze(ev,[{'claim_id':'chain','source':'S','target':'C'}]);assert o['claims'][0]['supported'];r['causal']='PASS'
    o=health_analyze(readj(s/'enterprise/collector_expectations.json')['sources'],readj(s/'enterprise/collector_observations.json')['sources'],None);assert not o['complete_mandatory'];r['collector_health']='PASS'
    v=readj(s/'protocols/a2a_verification.json');o=a2a_bind(load_jsonl(s/'protocols/a2a_events.jsonl'),v);assert 'a2a_undeclared_skill_invoked' in types(o);r['a2a_binding']='PASS'
    o=provider_normalize('openai',readj(s/'enterprise/openai_provider_export.json')['events'],False);assert o['events'];r['provider_normalization']='PASS'
    final={'schema':'ai-dfir/synthetic-scenario-result/v1.6','status':'PASS','components':r};(HERE/'fixtures/SYNTHETIC_SCENARIO_RESULT.json').write_text(json.dumps(final,indent=2,sort_keys=True), encoding='utf-8');print(json.dumps(final,indent=2,sort_keys=True))
if __name__=='__main__':main()
