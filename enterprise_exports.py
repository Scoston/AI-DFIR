#!/usr/bin/env python3
"""
Enterprise integrations export.

Generates files for downstream systems; it does not transmit them.
- OCSF 1.8.0 Incident Finding (class_uid 2005)
- Splunk HEC event envelope
- Generic signed webhook event
- Case interchange JSON

OCSF-specific AI runtime events remain available through ocsf_export.py.
"""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
from enterprise_case import CaseDB
from fleet_crypto import sign_payload

STATUS_ID={"OPEN":1,"TRIAGE":2,"INVESTIGATING":2,"CONTAINED":2,"RECOVERING":2,"CLOSED":5,"ARCHIVED":5}
SEV_ID={"low":2,"medium":3,"high":4,"critical":5}
def epoch_ms(s):
    from datetime import datetime
    return int(datetime.fromisoformat(s.replace("Z","+00:00")).timestamp()*1000)

def ocsf(case,activity_id=2):
    class_uid=2005
    return {
      "category_uid":2,"class_uid":class_uid,"activity_id":activity_id,
      "type_uid":class_uid*100+activity_id,
      "activity_name":{1:"Create",2:"Update",3:"Close"}.get(activity_id,"Update"),
      "time":epoch_ms(case["created_utc"]),
      "severity_id":SEV_ID.get(str(case["severity"]).lower(),1),
      "status_id":STATUS_ID.get(case["status"],2),
      "status":case["status"],
      "metadata":{"version":"1.8.0","profiles":["incident"],
                  "product":{"name":"AI-DFIR Enterprise","version":"1.0"}},
      "finding_info_list":[{
        "uid":case["case_id"],"title":case["title"],
        "types":["AI Incident Response"],
      }],
      "desc":case.get("summary"),
      "assignee":{"name":case.get("owner") or "unassigned"},
      "unmapped":{"ai_dfir_case_id":case["case_id"],"tenant_id":case.get("tenant_id"),
                  "tags":case.get("tags",[])},
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--cases-db",required=True);ap.add_argument("--case-id",required=True)
    ap.add_argument("--format",required=True,choices=["ocsf","splunk-hec","case-json","signed-webhook"])
    ap.add_argument("--out",required=True);ap.add_argument("--private-key")
    a=ap.parse_args();case=CaseDB(a.cases_db).get(a.case_id)
    if not case:raise KeyError(a.case_id)
    event=ocsf(case,3 if case["status"] in ("CLOSED","ARCHIVED") else 2)
    if a.format=="ocsf":obj=event
    elif a.format=="splunk-hec":obj={"time":time.time(),"host":"ai-dfir","source":"ai-dfir-enterprise",
                                    "sourcetype":"_json","event":event,
                                    "fields":{"case_id":case["case_id"],"tenant_id":case.get("tenant_id")}}
    elif a.format=="case-json":obj={"schema":"ai-dfir/case-interchange/v1.0","case":case}
    else:
        if not a.private_key:raise ValueError("--private-key required for signed-webhook")
        obj=sign_payload(Path(a.private_key),{"schema":"ai-dfir/webhook-event/v1.0","event":event})
    Path(a.out).write_text(json.dumps(obj,indent=2,sort_keys=True,default=str))
    print(a.out)
if __name__=="__main__":main()
