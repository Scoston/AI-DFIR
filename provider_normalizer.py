#!/usr/bin/env python3
"""Provider-export normalization contract for major AI platforms.

This reference adapter parses exported JSON/JSONL; it does not call provider APIs.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

PROVIDERS={'microsoft_copilot_foundry':{'request':['requestId','operationId'],'model':['model','deployment'],'actor':['userId','principalId'],'tool':['toolName'],'prompt':['prompt','input'],'response':['response','output']},'openai':{'request':['request_id','id'],'model':['model'],'actor':['user_id'],'tool':['tool_name'],'prompt':['input','messages'],'response':['output']},'anthropic':{'request':['request_id','id'],'model':['model'],'actor':['user_id'],'tool':['tool_name'],'prompt':['messages'],'response':['content']},'google_vertex':{'request':['request_id'],'model':['model'],'actor':['principal'],'tool':['tool'],'prompt':['contents'],'response':['candidates']},'aws_bedrock':{'request':['requestId'],'model':['modelId'],'actor':['principalArn'],'tool':['toolName'],'prompt':['input'],'response':['output']},'github_copilot':{'request':['request_id','correlation_id'],'model':['model'],'actor':['user'],'tool':['tool'],'prompt':['prompt'],'response':['completion']},'cursor':{'request':['request_id'],'model':['model'],'actor':['user'],'tool':['tool_name'],'prompt':['prompt'],'response':['response']}}

def first(o,keys):
    for k in keys:
        if k in o:return o[k]
    return None

def h(v):
    if v is None:return None
    if not isinstance(v,str):v=json.dumps(v,sort_keys=True,default=str)
    return hashlib.sha256(v.encode()).hexdigest()

def load(path):
    p=Path(path);txt=p.read_text(encoding='utf-8',errors='replace')
    try:
        o=json.loads(txt);return o if isinstance(o,list) else o.get('events',[o])
    except Exception:
        out=[]
        for line in txt.splitlines():
            try:out.append(json.loads(line))
            except Exception:pass
        return out

def normalize(provider,rows,include_content=False):
    m=PROVIDERS[provider];events=[]
    for i,r in enumerate(rows):
        req=first(r,m['request']);prompt=first(r,m['prompt']);resp=first(r,m['response']);tool=first(r,m['tool'])
        e={'schema':'ai-dfir/provider-event/v1.4','provider':provider,'event_id':f'{provider}:{req or i}','timestamp_utc':r.get('timestamp') or r.get('timestamp_utc') or r.get('time'),'request_id':req,'model':first(r,m['model']),'actor_id':first(r,m['actor']),'tool_name':tool,'prompt_sha256':h(prompt),'response_sha256':h(resp),'raw_event_sha256':h(r)}
        if include_content:e['prompt']=prompt;e['response']=resp
        events.append(e)
    return {'schema':'ai-dfir/provider-normalization/v1.4','provider':provider,'event_count':len(events),'events':events,'content_policy':'included' if include_content else 'hash_only'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--provider',choices=sorted(PROVIDERS),required=True);ap.add_argument('--input',required=True);ap.add_argument('--out',required=True);ap.add_argument('--include-content',action='store_true')
    a=ap.parse_args();o=normalize(a.provider,load(a.input),a.include_content);Path(a.out).write_text(json.dumps(o,indent=2,sort_keys=True,default=str));print(json.dumps({'provider':a.provider,'events':o['event_count']},indent=2))
if __name__=='__main__':main()
