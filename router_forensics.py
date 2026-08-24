#!/usr/bin/env python3
"""Model/provider routing and fallback forensics."""
from __future__ import annotations
import argparse,json
from collections import defaultdict
from pathlib import Path

def load_jsonl(path):
    out=[]
    for line in Path(path).read_text(encoding="utf-8",errors="replace").splitlines():
        if line.strip():
            try:out.append(json.loads(line))
            except Exception:pass
    return out

def analyze(policy,events):
    allowed_models=set(policy.get("allowed_models") or [])
    allowed_providers=set(policy.get("allowed_providers") or [])
    allowed_regions=set(policy.get("allowed_regions") or [])
    min_safety=policy.get("minimum_safety_profile")
    safety_rank={x:i for i,x in enumerate(policy.get("safety_profile_order") or [])}
    findings=[];routes=[]
    for e in events:
        requested=e.get("requested_model");resolved=e.get("resolved_model")
        provider=e.get("provider");region=e.get("region");safety=e.get("safety_profile")
        row={"request_id":e.get("request_id"),"requested_model":requested,"resolved_model":resolved,
             "provider":provider,"region":region,"safety_profile":safety,
             "fallback_reason":e.get("fallback_reason"),"router_version":e.get("router_version")}
        routes.append(row)
        if allowed_models and resolved not in allowed_models:
            findings.append({"type":"unapproved_model_resolution","severity":"critical","route":row})
        if allowed_providers and provider not in allowed_providers:
            findings.append({"type":"unapproved_provider","severity":"critical","route":row})
        if allowed_regions and region not in allowed_regions:
            findings.append({"type":"unapproved_model_region","severity":"high","route":row})
        if requested and resolved and requested!=resolved and not e.get("fallback_approved",False):
            findings.append({"type":"unapproved_model_failover","severity":"critical","route":row})
        if min_safety and safety_rank and safety_rank.get(safety,-1)<safety_rank.get(min_safety,999):
            findings.append({"type":"safety_policy_downgrade","severity":"critical","route":row,
                             "minimum":min_safety})
        if e.get("router_policy_sha256") and policy.get("router_policy_sha256") and e["router_policy_sha256"]!=policy["router_policy_sha256"]:
            findings.append({"type":"router_policy_drift","severity":"critical","route":row})
    return {"schema":"ai-dfir/model-router-analysis/v1.1","routes":routes,"findings":findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--policy",required=True);ap.add_argument("--log",required=True);ap.add_argument("--out")
    a=ap.parse_args();obj=analyze(json.loads(Path(a.policy).read_text()),load_jsonl(a.log))
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
