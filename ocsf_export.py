#!/usr/bin/env python3
"""
Export AI-DFIR live attestation evidence as OCSF 1.8-aligned Process Activity.

OCSF 1.8 added the ai_operation profile and ai_model/message_context objects.
This exporter uses Process Activity (class_uid 1007), activity_id 99 (Other),
and places AI-DFIR-specific forensic measurements in `unmapped`.

Run an OCSF validator in your target pipeline if strict schema conformance is
required, because deployments may use local extensions and later OCSF versions.
"""
import argparse, json
from datetime import datetime, timezone
from pathlib import Path


def epoch_ms(iso):
    try:
        return int(datetime.fromisoformat(iso.replace("Z","+00:00")).timestamp()*1000)
    except Exception:
        return None


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--attestation-log",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--model-name",default="Qwen3.8-27B")
    ap.add_argument("--model-provider",default="Qwen")
    ap.add_argument("--model-version",default=None)
    ap.add_argument("--schema-version",default="1.8.0")
    args=ap.parse_args()

    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    count=0
    with open(args.attestation_log,encoding="utf-8") as src, out.open("w",encoding="utf-8") as dst:
        for line in src:
            if not line.strip(): continue
            e=json.loads(line)
            if e.get("event_type")!="activation_attestation": continue
            measurements=e.get("measurements",{})
            rels=[m.get("relative_l2_to_exact_approved_activation") for m in measurements.values()
                  if isinstance(m.get("relative_l2_to_exact_approved_activation"),(int,float))]
            coses=[m.get("cosine_to_exact_approved_activation") for m in measurements.values()
                   if isinstance(m.get("cosine_to_exact_approved_activation"),(int,float))]
            t=epoch_ms(e.get("timestamp_utc",""))
            evt={
                "category_uid":1,
                "class_uid":1007,
                "activity_id":99,
                "type_uid":100799,
                "activity_name":"AI Runtime Attestation",
                "time":t,
                "severity_id":1,
                "metadata":{
                    "version":args.schema_version,
                    "profiles":["ai_operation"],
                    "product":{"name":"AI-DFIR Model Integrity","version":"0.4"},
                },
                "process":{
                    "pid":e.get("pid"),
                    "name":"model-inference-worker",
                },
                "ai_model":{
                    "name":args.model_name,
                    "ai_provider":args.model_provider,
                    "version":args.model_version or e.get("model_revision"),
                },
                "message_context":{
                    "session_uid":e.get("request_id"),
                },
                "unmapped":{
                    "ai_dfir_schema":"v0.4",
                    "prompt_sha256":e.get("prompt_sha256"),
                    "model_manifest_sha256":e.get("model_manifest_sha256"),
                    "fingerprint_sha256":e.get("fingerprint_sha256"),
                    "approved_activations_sha256":e.get("approved_activations_sha256"),
                    "captured_depths":e.get("captured_depths"),
                    "max_relative_l2":max(rels) if rels else None,
                    "min_exact_activation_cosine":min(coses) if coses else None,
                    "event_hash":e.get("event_hash"),
                    "prev_event_hash":e.get("prev_event_hash"),
                },
            }
            dst.write(json.dumps(evt,sort_keys=True)+"\n");count+=1
    print(f"Wrote {count} OCSF-aligned events to {out}")

if __name__=="__main__":main()
