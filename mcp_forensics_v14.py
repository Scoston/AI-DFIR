#!/usr/bin/env python3
"""MCP 2026-07-28 forensic analyzer: routing, auth, extensions, caches, Tasks, MRTR, Apps."""
from __future__ import annotations
import argparse,json,re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

TERMINAL={'completed','failed','cancelled','canceled','expired'}

def load(path):
    out=[]
    for line in Path(path).read_text(encoding='utf-8',errors='replace').splitlines():
        if line.strip():
            try:
                x=json.loads(line);out.extend(x if isinstance(x,list) else [x])
            except Exception:pass
    return [x for x in out if isinstance(x,dict)]

def origin(u):
    try:
        x=urlparse(u);return f'{x.scheme}://{x.netloc}' if x.scheme and x.netloc else None
    except Exception:return None

def analyze(rows,approved_app_origins=None,approved_extensions=None):
    app_orig=set(approved_app_origins or []);exts=set(approved_extensions or []);findings=[];tasks={};mrtr=defaultdict(list);catalog={};auth=[]
    for e in rows:
        h=e.get('headers') or {};method=e.get('mcp_method') or h.get('Mcp-Method') or e.get('method');name=e.get('mcp_name') or h.get('Mcp-Name') or e.get('tool_name')
        if not method:findings.append({'type':'mcp_missing_method_header_or_field','severity':'high','event':e})
        if method=='tools/call' and not name:findings.append({'type':'mcp_missing_name_for_tool_call','severity':'critical','event':e})
        body_method=e.get('body_method')
        if h.get('Mcp-Method') and body_method and h.get('Mcp-Method')!=body_method:findings.append({'type':'mcp_header_body_method_mismatch','severity':'critical','event':e})
        negotiated=set(e.get('extensions') or e.get('negotiated_extensions') or [])
        if exts and negotiated-exts:findings.append({'type':'mcp_unapproved_extension_negotiated','severity':'critical','extensions':sorted(negotiated-exts),'event':e})
        if e.get('catalog_type') in ('tools','prompts','resources') or method in ('tools/list','prompts/list','resources/list','resources/read'):
            ttl=e.get('ttlMs');scope=e.get('cacheScope');key=(method,e.get('server_id'),e.get('tenant_id'))
            if ttl is not None and (not isinstance(ttl,(int,float)) or ttl<0):findings.append({'type':'mcp_invalid_cache_ttl','severity':'high','event':e})
            if scope not in (None,'private','shared','tenant','session','none'):findings.append({'type':'mcp_unknown_cache_scope','severity':'high','event':e})
            if e.get('event')=='cache_read' and e.get('cache_expired'):findings.append({'type':'mcp_expired_catalog_cache_read','severity':'high','event':e})
            if scope=='shared' and e.get('tenant_id') and e.get('cached_tenant_id') not in (None,e.get('tenant_id')):findings.append({'type':'mcp_cross_tenant_catalog_cache','severity':'critical','event':e})
            old=catalog.get(key)
            if old and old.get('result_sha256') and e.get('result_sha256') and old['result_sha256']!=e['result_sha256'] and e.get('event')=='cache_read':findings.append({'type':'mcp_cached_catalog_content_changed','severity':'critical','event':e})
            catalog[key]=e
        if e.get('authorization') or e.get('issuer') or e.get('oauth'):
            auth.append(e);issuer=e.get('issuer');expected=e.get('expected_issuer')
            if expected and issuer!=expected:findings.append({'type':'mcp_authorization_issuer_mismatch','severity':'critical','expected':expected,'actual':issuer,'event':e})
            if e.get('issuer_validation_failed'):findings.append({'type':'mcp_authorization_issuer_validation_failed','severity':'critical','event':e})
            if e.get('pkce_method') and str(e.get('pkce_method')).upper()!='S256':findings.append({'type':'mcp_pkce_not_s256','severity':'critical','event':e})
            if e.get('protected_resource_metadata_required') and not e.get('protected_resource_metadata_present'):findings.append({'type':'mcp_protected_resource_metadata_missing','severity':'critical','event':e})
            if e.get('client_registration')=='DCR':findings.append({'type':'mcp_deprecated_dynamic_client_registration_observed','severity':'medium','event':e})
            if e.get('credential_issuer') and issuer and e.get('credential_issuer')!=issuer:findings.append({'type':'mcp_credential_issuer_binding_mismatch','severity':'critical','event':e})
        tid=e.get('task_id')
        if tid:
            t=tasks.setdefault(tid,{'state':None,'cancelled':False,'events':[],'subscribers':set()});t['events'].append(e);state=str(e.get('state') or e.get('status') or '').lower()
            if state:t['state']=state
            if method in ('tasks/cancel','tasks/update') and state in ('cancelled','canceled'):t['cancelled']=True
            elif t['cancelled'] and method in ('tasks/get','tools/call','tasks/update') and state not in TERMINAL:findings.append({'type':'mcp_task_activity_after_cancel','severity':'critical','task_id':tid,'event':e})
            if method=='subscriptions/listen':
                sub=e.get('subscriber_id') or e.get('principal');
                if sub:t['subscribers'].add(sub)
            if e.get('task_owner') and e.get('principal') and e['task_owner']!=e['principal']:findings.append({'type':'mcp_task_principal_mismatch','severity':'critical','task_id':tid,'event':e})
        rid=e.get('mrtr_id') or e.get('round_trip_id')
        if rid:
            mrtr[rid].append(e)
            if len(mrtr[rid])>int(e.get('max_round_trips') or 20):findings.append({'type':'mcp_mrtr_round_limit_exceeded','severity':'critical','mrtr_id':rid,'rounds':len(mrtr[rid])})
            if e.get('input_required') and not e.get('human_or_client_response_event_id'):findings.append({'type':'mcp_mrtr_input_required_without_response_link','severity':'high','event':e})
        uri=e.get('resource_uri') or e.get('ui_uri')
        if isinstance(uri,str) and uri.startswith('ui://'):
            if not e.get('app_content_sha256'):findings.append({'type':'mcp_app_missing_content_hash','severity':'high','event':e})
            for u in e.get('app_external_urls') or []:
                o=origin(u)
                if app_orig and o not in app_orig:findings.append({'type':'mcp_app_unapproved_external_origin','severity':'critical','origin':o,'event':e})
            if e.get('app_host_rpc_method') and not e.get('app_host_rpc_approved',False):findings.append({'type':'mcp_app_unapproved_host_rpc','severity':'critical','event':e})
    serial={k:{**{x:y for x,y in v.items() if x!='subscribers'},'subscribers':sorted(v['subscribers'])} for k,v in tasks.items()}
    return {'schema':'ai-dfir/mcp-2026-07-28-forensics/v1.4','task_count':len(tasks),'mrtr_count':len(mrtr),'authorization_event_count':len(auth),'tasks':serial,'mrtr':{k:len(v) for k,v in mrtr.items()},'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--log',required=True);ap.add_argument('--approved-app-origin',action='append',default=[]);ap.add_argument('--approved-extension',action='append',default=[]);ap.add_argument('--out')
    a=ap.parse_args();o=analyze(load(a.log),a.approved_app_origin,a.approved_extension);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
