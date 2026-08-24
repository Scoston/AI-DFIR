#!/usr/bin/env python3
"""A2A Agent Card observation history, rollback/key-rotation and signed-state drift."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from a2a_jcs import strict_load,prepare_agent_card,canonicalize

def card_state(card):
    payload=prepare_agent_card(card);body,engine=canonicalize(payload)
    sigs=[]
    for s in card.get("signatures") or []:
        try:
            import base64
            p=s["protected"]+"="*((4-len(s["protected"])%4)%4)
            h=json.loads(base64.urlsafe_b64decode(p))
            sigs.append({"kid":h.get("kid"),"alg":h.get("alg"),"jku":h.get("jku")})
        except Exception:sigs.append({"parse_error":True})
    return {
      "canonical_sha256":hashlib.sha256(body).hexdigest(),"canonicalization_engine":engine,
      "name":card.get("name"),"version":card.get("version"),"provider":card.get("provider"),
      "interfaces":card.get("supportedInterfaces") or [],"skills":sorted(x.get("id") for x in card.get("skills") or []),
      "securitySchemes":card.get("securitySchemes") or {},"capabilities":card.get("capabilities") or {},
      "signatures":sigs
    }

def compare(previous,current):
    a,b=card_state(previous),card_state(current);findings=[]
    content_changed=a["canonical_sha256"]!=b["canonical_sha256"]
    if content_changed and a["version"]==b["version"]:
        findings.append({"type":"a2a_card_content_changed_without_version_change","severity":"critical"})
    oldskills=set(a["skills"]);newskills=set(b["skills"])
    if newskills-oldskills:
        findings.append({"type":"a2a_card_skill_expansion","severity":"high","added_skills":sorted(newskills-oldskills)})
    if oldskills-newskills:
        findings.append({"type":"a2a_card_skill_removed","severity":"medium","removed_skills":sorted(oldskills-newskills)})
    if a["interfaces"]!=b["interfaces"]:
        findings.append({"type":"a2a_card_interface_changed","severity":"critical","previous":a["interfaces"],"current":b["interfaces"]})
    if a["securitySchemes"]!=b["securitySchemes"]:
        findings.append({"type":"a2a_card_security_scheme_changed","severity":"critical"})
    if a["capabilities"]!=b["capabilities"]:
        findings.append({"type":"a2a_card_capabilities_changed","severity":"high"})
    oldkids={x.get("kid") for x in a["signatures"] if x.get("kid")}
    newkids={x.get("kid") for x in b["signatures"] if x.get("kid")}
    if newkids-oldkids:
        findings.append({"type":"a2a_card_signing_key_rotation","severity":"medium","new_kids":sorted(newkids-oldkids)})
    if oldkids and newkids and not (oldkids & newkids):
        findings.append({"type":"a2a_card_signing_key_full_replacement","severity":"high","old":sorted(oldkids),"new":sorted(newkids)})
    return {"schema":"ai-dfir/a2a-card-history/v1.3","previous":a,"current":b,"findings":findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--previous",required=True);ap.add_argument("--current",required=True);ap.add_argument("--out")
    a=ap.parse_args();obj=compare(strict_load(a.previous),strict_load(a.current));text=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(text)
    else:print(text)
if __name__=="__main__":main()
