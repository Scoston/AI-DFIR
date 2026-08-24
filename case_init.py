#!/usr/bin/env python3
import argparse, json, os, uuid
from datetime import datetime, timezone
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case-id",default=None)
    ap.add_argument("--root",required=True)
    args=ap.parse_args()
    cid=args.case_id or f"AI-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
    root=Path(args.root)/cid
    dirs=[
        "00_case","01_runtime","02_suspect","03_reference","04_static_analysis",
        "05_approved_activations","06_fingerprint","07_suspect_activations",
        "08_live_attestation","09_baselines","10_replay","11_agent_trace",
        "12_hardware_attestation","13_timeline","14_ocsf","15_provenance_bundle",
        "16_reports","17_representation_intake","18_representation_integrity",
        "19_acquisition_trust","20_a2a_trust","21_platform_assurance","22_provider_certification","23_release_assurance","21_runtime_trust","22_workload_identity","23_memory_integrity","24_skill_supply_chain","25_otel_genai","26_causal_graph","27_collector_health","28_transparency","29_validation_lab","30_enterprise_metadata","31_provider_native","32_enterprise_identity","33_distributed_acquisition","34_legal_hold","35_dr_restore","36_case_exports","37_service_health"
    ]
    for d in dirs:(root/d).mkdir(parents=True,exist_ok=True)
    meta={
        "schema":"ai-dfir/case/v1.6","case_id":cid,
        "created_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        "tool_version":"1.6",
    }
    (root/"00_case"/"case.json").write_text(json.dumps(meta,indent=2,sort_keys=True))
    print(root)

if __name__=="__main__":main()
