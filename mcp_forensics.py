#!/usr/bin/env python3
"""
MCP forensic inventory/diff/analyzer for MCP 2026-07-28-era deployments.

The tool is passive: it analyzes exported server inventories, tool schemas,
authorization metadata, and request/response logs. It does not call MCP tools.

Important 2026-07-28 evidence:
- protocol version
- server identity and endpoint
- Mcp-Method / Mcp-Name routing fields where logged
- tools/prompts/resources catalogs and cache metadata
- Tasks extension lifecycle
- authorization issuer and client metadata
"""
from __future__ import annotations
import argparse, hashlib, json
from collections import Counter, defaultdict
from pathlib import Path

def canon(o):return json.dumps(o,sort_keys=True,separators=(",",":")).encode()
def digest(o):return hashlib.sha256(canon(o)).hexdigest()

def normalize_inventory(obj):
    servers=[]
    raw=obj.get("servers",obj if isinstance(obj,list) else [])
    for s in raw:
        tools=[]
        for t in s.get("tools",[]):
            tools.append({
                "name":t.get("name"),
                "description_sha256":hashlib.sha256((t.get("description") or "").encode()).hexdigest(),
                "input_schema_sha256":digest(t.get("inputSchema") or t.get("input_schema") or {}),
                "output_schema_sha256":digest(t.get("outputSchema") or t.get("output_schema") or {}),
            })
        servers.append({
            "server_id":s.get("server_id") or s.get("name") or s.get("url"),
            "url":s.get("url"),
            "protocol_version":s.get("protocol_version"),
            "authorization_issuer":s.get("authorization_issuer") or s.get("issuer"),
            "client_id":s.get("client_id"),
            "extensions":sorted(s.get("extensions") or []),
            "tools":sorted(tools,key=lambda x:str(x["name"])),
            "prompts_sha256":digest(s.get("prompts") or []),
            "resources_sha256":digest(s.get("resources") or []),
        })
    return sorted(servers,key=lambda x:str(x["server_id"]))

def diff(approved,suspect):
    a={x["server_id"]:x for x in normalize_inventory(approved)}
    b={x["server_id"]:x for x in normalize_inventory(suspect)}
    findings=[]
    for sid in sorted(set(b)-set(a)):
        findings.append({"type":"unexpected_mcp_server","severity":"critical","server_id":sid})
    for sid in sorted(set(a)-set(b)):
        findings.append({"type":"missing_approved_mcp_server","severity":"medium","server_id":sid})
    for sid in sorted(set(a)&set(b)):
        aa,bb=a[sid],b[sid]
        for field,sev in [("url","high"),("protocol_version","medium"),
                          ("authorization_issuer","critical"),("client_id","high"),
                          ("prompts_sha256","high"),("resources_sha256","high")]:
            if aa.get(field)!=bb.get(field):
                findings.append({"type":f"mcp_{field}_changed","severity":sev,"server_id":sid,
                                 "approved":aa.get(field),"suspect":bb.get(field)})
        at={x["name"]:x for x in aa["tools"]};bt={x["name"]:x for x in bb["tools"]}
        for name in sorted(set(bt)-set(at)):
            findings.append({"type":"unexpected_mcp_tool","severity":"critical","server_id":sid,"tool":name})
        for name in sorted(set(at)&set(bt)):
            for field in ("description_sha256","input_schema_sha256","output_schema_sha256"):
                if at[name][field]!=bt[name][field]:
                    findings.append({"type":"mcp_tool_schema_changed","severity":"critical",
                                     "server_id":sid,"tool":name,"field":field,
                                     "approved":at[name][field],"suspect":bt[name][field]})
    return findings

def analyze_logs(path:Path):
    rows=[]
    for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
        if not line.strip():continue
        try:rows.append(json.loads(line))
        except Exception:pass
    methods=Counter();tools=Counter();issuers=Counter();tasks=defaultdict(list);alerts=[]
    for e in rows:
        method=e.get("mcp_method") or e.get("method") or (e.get("headers") or {}).get("Mcp-Method")
        name=e.get("mcp_name") or (e.get("headers") or {}).get("Mcp-Name") or e.get("tool_name")
        if method:methods[method]+=1
        if name:tools[name]+=1
        issuer=e.get("authorization_issuer") or e.get("issuer")
        if issuer:issuers[issuer]+=1
        task=e.get("task_id")
        if task:tasks[task].append({"method":method,"status":e.get("status"),"timestamp_utc":e.get("timestamp_utc")})
        if e.get("authorization_error") or e.get("issuer_validation_failed"):
            alerts.append({"type":"mcp_authorization_failure","event":e})
    return {
        "schema":"ai-dfir/mcp-log-analysis/v0.9",
        "events":len(rows),"methods":dict(methods),"tools":dict(tools),"issuers":dict(issuers),
        "tasks":dict(tasks),"findings":alerts,
    }

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("inventory");p.add_argument("--input",required=True);p.add_argument("--out")
    p=sp.add_parser("diff");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out")
    p=sp.add_parser("logs");p.add_argument("--log",required=True);p.add_argument("--out")
    args=ap.parse_args()
    if args.cmd=="inventory":obj=normalize_inventory(json.loads(Path(args.input).read_text()))
    elif args.cmd=="diff":obj=diff(json.loads(Path(args.approved).read_text()),json.loads(Path(args.suspect).read_text()))
    else:obj=analyze_logs(Path(args.log))
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if getattr(args,"out",None):Path(args.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
