#!/usr/bin/env python3
"""Generate a synthetic AI-DFIR v1.6 Workbench demo case from bundled fixtures."""
from __future__ import annotations
import json, shutil, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
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

FIX=ROOT/'tests/fixtures/scenarios'
OUT=ROOT/'docs/demo/cases/DEMO-001'

def readj(p):return json.loads(Path(p).read_text())
def writej(name,obj):(OUT/name).write_text(json.dumps(obj,indent=2,sort_keys=True,default=str),encoding='utf-8')
def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

def main():
    shutil.rmtree(OUT,ignore_errors=True);OUT.mkdir(parents=True)
    writej('case.json',{
        'schema':'ai-dfir/case/v1.6','case_id':'DEMO-001','title':'Synthetic Agentic AI Incident','severity':'high',
        'status':'INVESTIGATING','tool_version':'1.6','created_utc':utc(),
        'summary':'Synthetic demo: representation deception, agent identity/authority drift, and incomplete provider telemetry.'
    })
    writej('evil_font_analysis.json',analyze_docx(FIX/'representation/evilfont_style.docx'))
    writej('unicode_analysis.json',unicode_analyze((FIX/'representation/unicode.md').read_text(encoding='utf-8')))
    writej('terminal_analysis.json',terminal_analyze((FIX/'representation/terminal_raw.log').read_text(encoding='utf-8',errors='replace')))
    writej('network_exfil_analysis.json',network_analyze(load_network(FIX/'agentic/network.jsonl'),['corp.example']))
    writej('browser_analysis.json',browser_analyze(readj(FIX/'agentic/browser_events.json')['events'],approved_ws_origins=['wss://trusted.example']))
    writej('cache_analysis.json',cache_analyze(readj(FIX/'agentic/cache_records.json')['records'],{'D':'H2'}))
    events=[json.loads(x) for x in (FIX/'agentic/router_events.jsonl').read_text().splitlines()]
    writej('router_analysis.json',router_analyze(readj(FIX/'agentic/router_policy.json'),events))
    writej('mcp_2026_forensics.json',mcp_analyze(readj(FIX/'protocols/mcp_events.json')['events'],['https://trusted.example'],[]))
    writej('otel_genai_ingest.json',otel_normalize(readj(FIX/'protocols/otel.json')))
    writej('memory_integrity_analysis.json',memory_analyze(readj(FIX/'runtime_trust/memory_events.json')['events'],None,['trusted']))
    writej('workload_identity_analysis.json',workload_analyze(readj(FIX/'runtime_trust/workload_events.json')['events'],['corp'],[]))
    writej('credential_lineage_analysis.json',credential_analyze(readj(FIX/'runtime_trust/credential_events.json')['events'],['https://idp.example']))
    writej('temporal_authority_analysis.json',authority_analyze(readj(FIX/'runtime_trust/authority_policy.json'),readj(FIX/'runtime_trust/authority_actions.json')['events']))
    writej('skill_supply_chain_diff.json',skill_diff(skill_inventory(FIX/'runtime_trust/skill_approved'),skill_inventory(FIX/'runtime_trust/skill_suspect')))
    writej('approval_integrity_analysis.json',approval_analyze(readj(FIX/'approval/approval_records.json')['records']))
    ev=[json.loads(x) for x in (FIX/'agentic/agentic_events.jsonl').read_text().splitlines()]
    writej('typed_causal_graph.json',causal_analyze(ev,[{'claim_id':'chain','source':'S','target':'C'}]))
    writej('collector_health.json',health_analyze(readj(FIX/'enterprise/collector_expectations.json')['sources'],readj(FIX/'enterprise/collector_observations.json')['sources'],None))
    verification=readj(FIX/'protocols/a2a_verification.json')
    writej('a2a_agent_card_verification.json',verification)
    writej('a2a_execution_binding.json',a2a_bind(load_jsonl(FIX/'protocols/a2a_events.jsonl'),verification))
    writej('provider_normalization.json',provider_normalize('openai',readj(FIX/'enterprise/openai_provider_export.json')['events'],False))
    # Platform assurance from synthetic passing controls, with one explicit provider/collector degradation.
    writej('platform_assurance_v16.json',{
      'schema':'ai-dfir/platform-assurance/v1.6','status':'DEGRADED','validated_utc':utc(),
      'controls':[
        {'control':'metadata_database','status':'PASS','detail':'HA/RLS evidence available'},
        {'control':'immutable_storage','status':'PASS','detail':'WORM evidence verified'},
        {'control':'kms','status':'PASS','detail':'Envelope-key control healthy'},
        {'control':'service_identity','status':'PASS','detail':'SPIFFE/mTLS identity verified'},
        {'control':'provider_telemetry','status':'DEGRADED','detail':'One mandatory provider source incomplete'},
        {'control':'collector_health','status':'DEGRADED','detail':'Expected 100 events; observed 71'}
      ],
      'findings':[{'type':'provider_telemetry_incomplete','severity':'high','source':'synthetic-provider'},
                  {'type':'collector_coverage_gap','severity':'high','expected':100,'observed':71}],
      'rule':'A platform evidence gap cannot be interpreted as clean incident evidence.'
    })
    writej('incident_profile.json',{
      'schema':'ai-dfir/incident-profile/v1.6','evidence_pack_id':'generic.evil_font_glyph_deception',
      'additional_evidence_pack_ids':['a2a.execution_identity_binding','runtime.temporal_authority_violation','enterprise.provider_collection_gap'],
      'alert_id':'DEMO-SYNTHETIC','source':'synthetic-demo'
    })
    print(json.dumps({'status':'PASS','case_root':str(OUT),'files':len(list(OUT.iterdir()))},indent=2))
if __name__=='__main__':main()
