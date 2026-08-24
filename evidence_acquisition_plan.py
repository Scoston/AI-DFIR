#!/usr/bin/env python3
"""Generate analyst acquisition plans and Microsoft Advanced Hunting starter queries."""
import argparse
from pathlib import Path
from evidence_pack_engine import get_pack

KQL={
'AlertInfo': 'AlertInfo\n| where AlertId == "<ALERT_ID>"\n| project Timestamp, AlertId, Title, Severity, Category, DetectionSource, ServiceSource, IncidentId',
'AlertEvidence': 'AlertEvidence\n| where AlertId == "<ALERT_ID>"\n| order by Timestamp asc',
'CloudAppEvents': 'CloudAppEvents\n| where Timestamp between (datetime(<START_UTC>) .. datetime(<END_UTC>))\n| where RawEventData has "<AGENT_OR_ENTITY_ID>"\n| order by Timestamp asc',
'AgentsInfo': 'AgentsInfo\n| summarize arg_max(Timestamp, *) by AgentId\n| where AgentId == "<AGENT_ID>"',
'BehaviorInfo': 'BehaviorInfo\n| where Timestamp between (datetime(<START_UTC>) .. datetime(<END_UTC>))\n| order by Timestamp asc',
'BehaviorEntities': 'BehaviorEntities\n| where Timestamp between (datetime(<START_UTC>) .. datetime(<END_UTC>))\n| order by Timestamp asc',
'MDE endpoint': 'union DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents\n| where DeviceId == "<DEVICE_ID>"\n| where Timestamp between (datetime(<START_UTC>) .. datetime(<END_UTC>))\n| order by Timestamp asc'
}

def make(pack):
    lines=[f"# Acquisition Plan — {pack['title']}",'',f"Pack: `{pack['id']}`",'']
    for pri in ['mandatory','conditional','optional']:
        xs=[x for x in pack.get('artifacts',[]) if x.get('priority')==pri]
        if not xs:continue
        lines += [f"## {pri.title()} evidence",'']
        for x in xs:
            lines += [f"### {x['title']}",f"Why: {x.get('rationale','')}"]
            if x.get('condition'):lines.append(f"Condition: {x['condition']}")
            if x.get('locations'):lines.append('Likely locations: '+', '.join(f'`{z}`' for z in x['locations']))
            if x.get('collection_guidance'):lines.append('Collection: '+x['collection_guidance'])
            if x.get('validation'):
                v=x['validation']
                lines.append('Validation: '+', '.join(f"{k}={v[k]}" for k in sorted(v)))
            lines.append('')
    if pack.get('vendor')=='Microsoft':
        lines += ['## Microsoft Advanced Hunting starter queries','', 'Replace placeholders and constrain the time window.','']
        for name,q in KQL.items():lines += [f"### {name}",'```kusto',q,'```','']
    return '\n'.join(lines)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--pack',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    Path(a.out).write_text(make(get_pack(a.pack)),encoding='utf-8');print(a.out)
