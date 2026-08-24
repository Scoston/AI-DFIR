#!/usr/bin/env python3
"""Detect suspicious DNS/URL exfiltration characteristics in AI-agent network logs."""
from __future__ import annotations
import argparse, json, math, re
from collections import Counter,defaultdict
from pathlib import Path
from urllib.parse import urlparse

HEX=re.compile(r"^[0-9a-fA-F]{20,}$")
B32=re.compile(r"^[A-Z2-7]{20,}$",re.I)
B64URL=re.compile(r"^[A-Za-z0-9_-]{24,}$")
def entropy(s):
    if not s:return 0
    c=Counter(s);n=len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def registrable_approx(host):
    p=host.strip(".").lower().split(".")
    return ".".join(p[-2:]) if len(p)>=2 else host.lower()
def load(path):
    out=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out
def analyze(rows,approved_domains=None):
    approved={x.lower() for x in (approved_domains or [])};findings=[];bybase=defaultdict(set)
    for e in rows:
        host=e.get("hostname") or e.get("query_name")
        url=e.get("url")
        if not host and url:
            try:host=urlparse(url).hostname
            except Exception:host=None
        if not host:continue
        host=host.rstrip(".").lower();base=registrable_approx(host);bybase[base].add(host)
        labels=host.split(".")[:-2] if host.count(".")>=2 else []
        for lab in labels:
            ent=entropy(lab)
            encoded=bool(HEX.match(lab) or B32.match(lab) or B64URL.match(lab))
            if len(lab)>=24 and (encoded or ent>=3.6):
                findings.append({"type":"dns_data_like_subdomain_label","severity":"high","hostname":host,
                                 "label_length":len(lab),"entropy":round(ent,3)})
        if approved and not any(host==d or host.endswith("."+d) for d in approved):
            if (e.get("source") or e.get("metadata",{}).get("source")) in ("agent","tool","rendered_output"):
                findings.append({"type":"agent_network_to_unapproved_domain","severity":"high","hostname":host,"event":e})
        if e.get("channel")=="dns" and (e.get("metadata") or {}).get("contains_sensitive_source_hash"):
            findings.append({"type":"dns_query_correlated_with_sensitive_source","severity":"critical","hostname":host,"event":e})
    for base,hosts in bybase.items():
        if len(hosts)>=20:
            findings.append({"type":"dns_high_unique_subdomain_fanout","severity":"high","base_domain":base,"unique_hosts":len(hosts)})
    return {"schema":"ai-dfir/network-exfil-analysis/v1.2","findings":findings}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--log",required=True);ap.add_argument("--approved-domain",action="append",default=[]);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(load(a.log),a.approved_domain);s=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(s)
    else:print(s)
if __name__=="__main__":main()
