#!/usr/bin/env python3
"""Time-aware effective authority and observed-vs-reachable blast-radius analysis."""
from __future__ import annotations
import argparse,json
from datetime import datetime
from pathlib import Path

def dt(s):return datetime.fromisoformat(str(s).replace('Z','+00:00')) if s else None

def active(x,t):
    nb=dt(x.get('not_before_utc'));ex=dt(x.get('expires_utc'));rev=dt(x.get('revoked_utc'))
    return not ((nb and t<nb) or (ex and t>=ex) or (rev and t>=rev) or x.get('disabled',False))

def scope_match(grant,ctx):
    if grant.get('tenant') not in (None,ctx.get('tenant')):return False
    if grant.get('resource') not in (None,'*',ctx.get('resource')):return False
    purposes=grant.get('purposes') or []
    if purposes and ctx.get('purpose') not in purposes:return False
    return True

def evaluate(policy,timestamp,principal,ctx=None):
    ctx=ctx or {};t=dt(timestamp);allow=set();deny=set();sources={}
    for g in policy.get('grants',[]):
        if g.get('principal')!=principal or not active(g,t) or not scope_match(g,ctx):continue
        for s in g.get('scopes') or []:allow.add(s);sources.setdefault(s,[]).append(g.get('grant_id') or 'grant')
    for d in policy.get('denies',[]):
        if d.get('principal') not in (principal,'*') or not active(d,t) or not scope_match(d,ctx):continue
        deny.update(d.get('scopes') or [])
    scopes=allow-deny
    return {'principal':principal,'timestamp_utc':timestamp,'context':ctx,'scopes':sorted(scopes),'denied_scopes':sorted(deny),'sources':sources}

def analyze(policy,events):
    findings=[];observed=[];maxreach={}
    tools={x['id']:x for x in policy.get('tools',[])}
    principals=sorted({g.get('principal') for g in policy.get('grants',[]) if g.get('principal')})
    # maximum reachable across all valid grants at the event's time/context is reported per observed action
    for e in events:
        if e.get('event_type') not in ('tool_call','action','api_call','data_write','network_action'):continue
        principal=e.get('principal') or e.get('actor_id');ctx={'tenant':e.get('tenant'),'resource':e.get('resource') or e.get('target_id'),'purpose':e.get('purpose')}
        state=evaluate(policy,e.get('timestamp_utc'),principal,ctx);tool=tools.get(e.get('tool_id') or e.get('tool_name') or e.get('target_id'),{})
        req=set(tool.get('requires_scopes') or e.get('required_scopes') or [])
        have=set(state['scopes']);missing=sorted(req-have)
        if missing:findings.append({'type':'action_exceeded_temporal_authority','severity':'critical','event_id':e.get('event_id'),'principal':principal,'missing_scopes':missing,'authority':state})
        if e.get('approval_required') and not e.get('approval_event_id'):findings.append({'type':'temporal_authority_missing_required_approval','severity':'critical','event_id':e.get('event_id')})
        cred_exp=dt(e.get('credential_expires_utc'));ts=dt(e.get('timestamp_utc'))
        if cred_exp and ts and ts>=cred_exp:findings.append({'type':'authority_backed_by_expired_credential','severity':'critical','event_id':e.get('event_id')})
        observed.append({'event_id':e.get('event_id'),'tool':e.get('tool_id') or e.get('tool_name'),'required_scopes':sorted(req),'authorized':not missing,'authority':state})
    # snapshot max authority at optional incident time, or latest event time.
    times=[dt(e.get('timestamp_utc')) for e in events if e.get('timestamp_utc')]
    t=max(times) if times else datetime.now().astimezone()
    for p in principals:
        st=evaluate(policy,t.isoformat(),p,{})
        reach=[]
        for tid,tool in tools.items():
            if set(tool.get('requires_scopes') or []).issubset(set(st['scopes'])):reach.append(tid)
        maxreach[p]={'scopes':st['scopes'],'reachable_tools':sorted(reach)}
    return {'schema':'ai-dfir/temporal-authority/v1.4','observed_actions':observed,'maximum_reachable':maxreach,'findings':findings,
            'rule':'Authority is evaluated at action time with grant/deny, resource, tenant, purpose, credential, and approval context.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--policy',required=True);ap.add_argument('--events',required=True);ap.add_argument('--out')
    a=ap.parse_args();p=json.loads(Path(a.policy).read_text());e=json.loads(Path(a.events).read_text());e=e.get('events',e)
    o=analyze(p,e);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
