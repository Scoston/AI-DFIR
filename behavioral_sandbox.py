#!/usr/bin/env python3
"""Safe behavioral-sandbox policy generator and declared-vs-observed analyzer.

This module does NOT execute untrusted code. It defines a sandbox contract and
analyzes telemetry produced by an external isolated canary/detonation system.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path

def plan(name='ai-dfir-canary'):
    return {'schema':'ai-dfir/behavioral-sandbox-plan/v1.4','name':name,'execution_performed_by_this_tool':False,
            'isolation':{'network_default':'deny','allowed_network':['sinkhole.local'],'host_filesystem':'none','workspace':'ephemeral_copy','credentials':'synthetic_only','secrets':'none','privileged':False,'user':'nonroot','process_limit':64,'cpu_seconds':60,'memory_mb':1024,'wall_seconds':120},
            'instrumentation':['process','file_read','file_write','dns','http','websocket','tool_call','memory_write','identity_file_write','credential_access_attempt'],
            'required_controls':['no_real_credentials','no_production_tokens','no_host_home_mount','no_unrestricted_egress','capture_complete_telemetry']}

def analyze(declared,observed):
    declared_caps=set(declared.get('capabilities') or []);declared_files=set(declared.get('file_paths') or []);declared_domains=set(declared.get('network_domains') or []);findings=[]
    obs_caps=set();
    for e in observed:
        typ=e.get('event_type');
        if typ:obs_caps.add(typ)
        path=e.get('path');host=e.get('hostname') or e.get('domain')
        if path and declared_files and path not in declared_files:findings.append({'type':'sandbox_undeclared_file_access','severity':'high','path':path,'event':e})
        if host and declared_domains and host not in declared_domains:findings.append({'type':'sandbox_undeclared_network_destination','severity':'critical','hostname':host,'event':e})
        if typ in ('credential_access_attempt','identity_file_write','memory_write') and typ not in declared_caps:findings.append({'type':'sandbox_undeclared_sensitive_behavior','severity':'critical','behavior':typ,'event':e})
    unexpected=sorted(obs_caps-declared_caps)
    if unexpected:findings.append({'type':'sandbox_declared_observed_capability_mismatch','severity':'high','unexpected_capabilities':unexpected})
    return {'schema':'ai-dfir/behavioral-sandbox-analysis/v1.4','declared':declared,'observed_capabilities':sorted(obs_caps),'findings':findings,
            'rule':'Telemetry is analyzed; AI-DFIR does not execute the suspect artifact.'}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('plan');p.add_argument('--name',default='ai-dfir-canary');p.add_argument('--out')
    p=sp.add_parser('analyze');p.add_argument('--declared',required=True);p.add_argument('--observed',required=True);p.add_argument('--out')
    a=ap.parse_args();o=plan(a.name) if a.cmd=='plan' else analyze(json.loads(Path(a.declared).read_text()),json.loads(Path(a.observed).read_text()).get('events',json.loads(Path(a.observed).read_text())))
    s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
