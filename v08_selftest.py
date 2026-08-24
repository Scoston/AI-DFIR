#!/usr/bin/env python3
from pathlib import Path
import argparse,json,shutil,sys,tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from evidence_pack_engine import load_packs,get_pack,resolve,assess,create_profile
from evidence_acquisition_plan import make as acquisition_plan
from universal_provider_adapter import find as provider_find
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

def touch(p:Path,data='{}'):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data,encoding='utf-8')

def claude_case(root:Path):
    touch(root/'case.json',json.dumps({'case_id':'CLAUDE-PI-001','tool_version':'0.8'}))
    create_profile(root,'anthropic.claude_code.prompt_injection',alert_title='Suspicious AI prompt injection',agent='Claude Code')
    touch(root/'.claude/projects/proj/session.jsonl','{"type":"message"}\n')
    touch(root/'.claude/history.jsonl','{"prompt":"test"}\n')
    touch(root/'.claude/projects/proj/session/tool-results/result.txt','tool output')
    touch(root/'CLAUDE.md','project instructions')
    touch(root/'.claude/settings.json','{}')
    touch(root/'.claude.json','{}')
    touch(root/'.mcp.json','{}')
    touch(root/'hooks/hooks.json','{}')
    touch(root/'DeviceProcessEvents.json','[]')
    return root

def ascii_case(root:Path,complete=True):
    touch(root/'case.json',json.dumps({'case_id':'MS-ASCII-001','tool_version':'0.8'}))
    create_profile(root,'microsoft.AI.Azure_ASCIISmuggling',alert_id='AI.Azure_ASCIISmuggling')
    touch(root/'AlertInfo.json','[]')
    if complete:
        touch(root/'AlertEvidence.json','[]');touch(root/'signin.json','[]');touch(root/'request_response.json','[]')
        (root/'raw_bytes.bin').write_bytes(b'raw')
        touch(root/'decoded_unicode.txt','decoded');touch(root/'source_document.html','<p>source</p>');touch(root/'agent_trace.jsonl','{}\n')
    return root

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);args=ap.parse_args()
    out=Path(args.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)
    result={}

    packs=load_packs();ids=[p['id'] for p in packs]
    assert len(ids)==len(set(ids));assert len(packs)>=26
    for p in packs:
        assert p.get('schema')=='ai-dfir/evidence-pack/v0.8'
        assert p.get('artifacts')
        aids={a['id'] for a in p['artifacts']}
        for a in p['artifacts']:
            assert a.get('priority') in ('mandatory','conditional','optional')
            assert a.get('rationale') and a.get('presence_patterns') is not None
        for g in p.get('conclusion_gates',[]):
            for req in g.get('requires',[]):
                aliases=(g.get('allow_aliases') or {}).get(req,[])
                assert req in aids or aliases, (p['id'],req)
    result['pack_schema_validation']='PASS'

    for aid in MS_IDS:
        rows=resolve(alert_id=aid);assert rows and rows[0]['score']>=100
        assert aid in rows[0]['pack'].get('match',{}).get('alert_ids',[])
    k=resolve(alert_title='Exposed Kubernetes service detected')
    assert k and k[0]['pack']['id']=='microsoft.ExposedKubernetesService.AI'
    catalog=json.loads((HERE/'MICROSOFT_AI_ALERT_CATALOG.json').read_text())
    assert len(catalog['alerts'])==18
    result['microsoft_current_alert_catalog']='PASS'

    a365=get_pack('microsoft.agent365.ai_threat_detection')
    assert not (a365.get('match',{}).get('alert_ids') or [])
    assert len(a365['match']['detection_families'])>=7
    result['agent365_no_invented_ids']='PASS'

    claude=get_pack('anthropic.claude_code.prompt_injection')
    required={'session_transcript','prompt_history','tool_results','claude_md','settings','claude_state','mcp_config','hooks','endpoint_telemetry'}
    assert required.issubset({x['id'] for x in claude['artifacts'] if x['priority']=='mandatory'})
    cc=claude_case(out/'claude_case');ca=assess(claude,cc)
    assert ca['mandatory_complete'] is True,[(x['id'],x['status']) for x in ca['artifacts'] if x['priority']=='mandatory']
    fc=full_case(cc);assert fc['evidence_pack']['selected'] and fc['evidence_pack']['assessment']['mandatory_complete']
    report=markdown(fc);assert 'Incident Evidence Pack & Sufficiency' in report and 'Claude Code' in report
    result['claude_code_prompt_injection_workflow']='PASS'

    mp=get_pack('microsoft.AI.Azure_ASCIISmuggling');mc=ascii_case(out/'ascii_case',True);ma=assess(mp,mc)
    assert ma['mandatory_complete'] is True,[(x['id'],x['status']) for x in ma['artifacts'] if x['priority']=='mandatory']
    assert any(g['id']=='event_confirmed' and g['status']=='supported' for g in ma['conclusion_gates'])
    result['microsoft_ascii_smuggling_workflow']='PASS'

    miss=ascii_case(out/'ascii_missing',False);mma=assess(mp,miss)
    assert mma['mandatory_complete'] is False and mma['mandatory_percent']<100
    assert any(g['status']=='not_supported' for g in mma['conclusion_gates'])
    result['missing_evidence_not_clean']='PASS'

    plan=acquisition_plan(get_pack('microsoft.AI.Azure_AnomalousToolInvocation'))
    for table in ['AlertInfo','AlertEvidence','CloudAppEvents','AgentsInfo','BehaviorInfo','BehaviorEntities','DeviceProcessEvents']:
        assert table in plan
    result['microsoft_hunting_plan']='PASS'

    assert provider_find('Qwen')[0]['forensic_mode']=='white-box'
    assert provider_find('Claude Code')[0]['forensic_mode']=='gray-box'
    assert provider_find('Azure OpenAI')
    result['universal_provider_modes']='PASS'

    dash=(HERE/'analyst_dashboard.py').read_text()
    assert 'Incident Evidence Pack & Conclusion Sufficiency' in dash and "version':'0.8" in dash
    result['workbench_integration']='PASS'

    final={'status':'PASS','pack_count':len(packs),'microsoft_defender_for_cloud_pack_count':18,'components':result}
    (out/'V0.8_SELFTEST.json').write_text(json.dumps(final,indent=2,sort_keys=True))
    print(json.dumps(final,indent=2,sort_keys=True))
if __name__=='__main__':main()
