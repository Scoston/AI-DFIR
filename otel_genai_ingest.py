#!/usr/bin/env python3
"""Normalize OpenTelemetry GenAI spans into AI-DFIR agentic events."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

OPMAP={'create_agent':'agent_birth','invoke_agent':'agent_invoke','invoke_workflow':'workflow_invoke','plan':'plan','execute_tool':'tool_call','retrieval':'retrieval_result','search_memory':'memory_read','create_memory':'memory_write','update_memory':'memory_update','upsert_memory':'memory_upsert','delete_memory':'memory_delete','generate_content':'model_inference','chat':'model_inference','text_completion':'model_inference'}

def attrs(x):
    a=x.get('attributes') or {};out={}
    if isinstance(a,list):
        for i in a:
            k=i.get('key');v=i.get('value') or {};out[k]=next(iter(v.values())) if isinstance(v,dict) and v else v
    elif isinstance(a,dict):out=a
    return out

def walk(obj):
    if isinstance(obj,dict):
        if ('spanId' in obj or 'span_id' in obj) and ('traceId' in obj or 'trace_id' in obj):yield obj
        for v in obj.values():yield from walk(v)
    elif isinstance(obj,list):
        for v in obj:yield from walk(v)

def hash_content(v):
    if v is None:return None
    if not isinstance(v,str):v=json.dumps(v,sort_keys=True,default=str)
    return hashlib.sha256(v.encode()).hexdigest()

def normalize(doc,include_content=False):
    events=[];ops={};missing=[]
    for s in walk(doc):
        a=attrs(s);op=a.get('gen_ai.operation.name') or a.get('gen_ai.operation_name') or a.get('operation.name')
        if not op:continue
        ops[op]=ops.get(op,0)+1;trace=s.get('traceId') or s.get('trace_id');span=s.get('spanId') or s.get('span_id');parent=s.get('parentSpanId') or s.get('parent_span_id')
        eid=f'otel:{trace}:{span}';etype=OPMAP.get(op,'otel_genai_operation')
        meta={'otel.trace_id':trace,'otel.span_id':span,'otel.parent_span_id':parent,'gen_ai.operation.name':op,'gen_ai.agent.id':a.get('gen_ai.agent.id'),'gen_ai.agent.name':a.get('gen_ai.agent.name'),'gen_ai.conversation.id':a.get('gen_ai.conversation.id'),'gen_ai.request.model':a.get('gen_ai.request.model'),'gen_ai.response.model':a.get('gen_ai.response.model'),'gen_ai.tool.call.id':a.get('gen_ai.tool.call.id'),'gen_ai.tool.name':a.get('gen_ai.tool.name'),'gen_ai.data_source.id':a.get('gen_ai.data_source.id'),'error.type':a.get('error.type')}
        content=a.get('gen_ai.input.messages') or a.get('gen_ai.input') or a.get('gen_ai.output.messages') or a.get('gen_ai.output')
        ev={'schema':'ai-dfir/agentic-event/v1.4','event_id':eid,'event_type':etype,'actor_id':a.get('gen_ai.agent.id') or a.get('service.name'),'target_id':a.get('gen_ai.tool.name') or a.get('gen_ai.data_source.id') or a.get('gen_ai.request.model'),'timestamp_utc':s.get('startTimeUnixNano') or s.get('start_time') or s.get('timestamp_utc'),'parent_event_id':f'otel:{trace}:{parent}' if parent else None,'cause_event_ids':[],'correlation_ids':[f'trace:{trace}'],'session_id':a.get('gen_ai.conversation.id'),'content_sha256':hash_content(content),'metadata':meta}
        if include_content and content is not None:ev['metadata']['captured_content']=content
        events.append(ev)
    coverage={'spans_seen':len(list(walk(doc))),'genai_spans_normalized':len(events),'operations':ops}
    if not events:missing.append('no recognized gen_ai.operation.name spans')
    return {'schema':'ai-dfir/otel-genai-ingest/v1.4','events':events,'coverage':coverage,'findings':[{'type':'otel_genai_coverage_gap','severity':'high','detail':x} for x in missing],'content_policy':'hash_only' if not include_content else 'content_included_by_explicit_request'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--input',required=True);ap.add_argument('--out',required=True);ap.add_argument('--events-out');ap.add_argument('--include-content',action='store_true')
    a=ap.parse_args();doc=json.loads(Path(a.input).read_text());o=normalize(doc,a.include_content);Path(a.out).write_text(json.dumps(o,indent=2,sort_keys=True,default=str))
    if a.events_out:
        with Path(a.events_out).open('w') as f:
            for e in o['events']:f.write(json.dumps(e,sort_keys=True,default=str)+'\n')
    print(json.dumps({'normalized':len(o['events']),'out':a.out},indent=2))
if __name__=='__main__':main()
