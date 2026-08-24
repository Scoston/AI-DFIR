#!/usr/bin/env python3
"""
Enterprise incident closure-readiness gate.

A case is not "clean" merely because no additional alert fired. The gate checks:
- selected Evidence Pack mandatory sufficiency
- conclusion gates (unsupported conclusions are surfaced)
- unresolved downstream consequences
- containment/recovery state
- repository integrity

The output is advisory by default so organizations can define formal closure policy.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from case_model import full_case
from evidence_repository import Repository

def assess(workspace,repository=None,repo_key=None):
    case=full_case(Path(workspace))
    blockers=[];warnings=[]
    ep=case.get("evidence_pack") or {}
    if ep.get("selected"):
        missing=(ep.get("mandatory_total",0)-ep.get("mandatory_present",0))
        if missing>0:blockers.append({"type":"mandatory_evidence_missing","reason":"missing_or_below_v1_1_quality_threshold","count":missing})
        for a in ep.get("assessments") or []:
            unsupported=[g for g in a.get("conclusion_gates",[]) if g.get("status")!="supported"]
            if unsupported:warnings.append({"type":"unsupported_conclusions","pack_id":a.get("pack_id"),
                                            "gates":[g.get("id") for g in unsupported]})
    else:warnings.append({"type":"no_evidence_pack_selected"})
    en16=case.get("enterprise_v16") or {}
    pa=en16.get("platform_assurance") or {}
    if pa and pa.get("status") in ("CRITICAL","DEGRADED"):
        warnings.append({"type":"platform_assurance_not_healthy","status":pa.get("status"),"findings":pa.get("findings",[])})
    sec=en16.get("security_assurance") or {}
    if sec and sec.get("valid") is False:
        warnings.append({"type":"independent_security_assurance_gap","findings":sec.get("findings",[])})
    certs=en16.get("provider_certifications") or []
    badcert=[x for x in certs if x.get("certified") is not True]
    if badcert:
        warnings.append({"type":"provider_adapter_not_currently_certified","providers":[x.get("provider") for x in badcert]})
    en=case.get("enterprise_v15") or {}
    critical_en=[x for x in en.get("findings",[]) if x.get("severity")=="critical" and not x.get("resolved",False)]
    if critical_en:blockers.append({"type":"enterprise_v15_critical_findings_unresolved","count":len(critical_en),"findings":critical_en[:50]})
    gaps=en.get("provider_gaps") or []
    incomplete=[g for g in gaps if g.get("complete_mandatory") is not True]
    if incomplete:blockers.append({"type":"provider_mandatory_evidence_incomplete","providers":[g.get("provider") for g in incomplete],"details":incomplete})
    partial=[r for r in en.get("provider_receipts") or [] if r.get("collection_complete") is False]
    if partial:warnings.append({"type":"provider_collection_receipt_partial","count":len(partial),"sources":[r.get("source") for r in partial]})
    oidc=en.get("oidc_identity") or {}
    if oidc and oidc.get("trusted") is False:blockers.append({"type":"oidc_identity_untrusted_at_incident_time","findings":oidc.get("findings",[])})
    spiffe=en.get("spiffe_identity") or {}
    if spiffe and spiffe.get("trusted") is False:blockers.append({"type":"spiffe_service_identity_untrusted_at_incident_time","findings":spiffe.get("findings",[])})
    obj=en.get("object_store") or {}
    if obj and obj.get("valid") is False:blockers.append({"type":"enterprise_object_store_integrity_failure","findings":obj.get("findings",[])})
    slo=en.get("service_slo") or {}
    if slo and slo.get("pass") is False:blockers.append({"type":"evidence_collection_service_slo_failed","findings":slo.get("findings",[])})
    ready=en.get("production_readiness") or {}
    if ready and ready.get("production_ready") is False:warnings.append({"type":"deployment_not_production_ready","findings":ready.get("findings",[])})
    rt=case.get("runtime_trust") or {}
    critical_rt=[x for x in rt.get("findings",[]) if x.get("severity")=="critical" and not x.get("resolved",False)]
    if critical_rt:blockers.append({"type":"runtime_trust_critical_findings_unresolved","count":len(critical_rt),"findings":critical_rt[:50]})
    health=rt.get("collector_health") or {}
    if health and health.get("complete_mandatory") is False:blockers.append({"type":"mandatory_evidence_collection_incomplete","findings":health.get("findings",[])})
    peer=rt.get("peer_review") or {}
    if peer and peer.get("ready") is False:blockers.append({"type":"peer_review_incomplete","findings":peer.get("findings",[])})
    at=case.get("a2a_trust") or {}
    ver=at.get("verification") or {}
    if ver and not ver.get("policy_satisfied",False):
        blockers.append({"type":"a2a_agent_card_trust_policy_unsatisfied","findings":ver.get("findings",[])})
    bind=at.get("execution_binding") or {}
    critical_a2a=[x for x in bind.get("findings",[]) if x.get("severity")=="critical"]
    if critical_a2a:
        blockers.append({"type":"a2a_execution_identity_binding_unresolved","count":len(critical_a2a)})
    ri=case.get("representation_integrity") or {}
    intake=ri.get("intake") or {}
    if intake.get("verdict")=="QUARANTINE":
        blockers.append({"type":"quarantined_adversarial_content_unresolved"})
    trust=ri.get("acquisition_trust") or {}
    if trust and not trust.get("valid",False):
        blockers.append({"type":"acquisition_trust_verification_failed","findings":trust.get("findings",[])})
    ex=case.get("execution_integrity") or {}
    outstanding=(ex.get("session_task") or {}).get("outstanding_count")
    if isinstance(outstanding,int) and outstanding>0:
        blockers.append({"type":"outstanding_delegated_work","count":outstanding})
    for assessment in ep.get("assessments") or []:
        conflicting=[x for x in assessment.get("artifacts",[]) if x.get("quality")=="CONFLICTING" and x.get("priority")=="mandatory"]
        if conflicting:
            blockers.append({"type":"conflicting_mandatory_evidence","pack_id":assessment.get("pack_id"),
                             "artifacts":[x.get("id") for x in conflicting]})
    oc=(case.get("consequences") or {}).get("open_count")
    if isinstance(oc,int) and oc>0:blockers.append({"type":"open_consequences","count":oc})
    mode=(case.get("containment") or {}).get("control",{}).get("mode")
    if mode and mode not in ("released","observe"):blockers.append({"type":"containment_not_released","mode":mode})
    repo_integrity=None
    if repository:
        repo=Repository(repository,repo_key);repo_integrity=repo.verify()
        if not repo_integrity["valid"]:blockers.append({"type":"repository_integrity_failure","findings":repo_integrity["findings"]})
    return {"schema":"ai-dfir/closure-readiness/v1.6","ready":not blockers,
            "blockers":blockers,"warnings":warnings,"repository_integrity":repo_integrity}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--workspace",required=True);ap.add_argument("--repository");ap.add_argument("--repository-key-hex");ap.add_argument("--out")
    a=ap.parse_args();obj=assess(a.workspace,a.repository,bytes.fromhex(a.repository_key_hex) if a.repository_key_hex else None)
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
    if not obj["ready"]:raise SystemExit(2)
if __name__=="__main__":main()
