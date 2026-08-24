#!/usr/bin/env python3
"""Evidence-request task tracking derived from Evidence Pack sufficiency."""
from __future__ import annotations
import argparse,json,sqlite3,uuid
from datetime import datetime,timezone
from pathlib import Path
from evidence_pack_engine import get_pack, assess as assess_pack

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
class TaskDB:
    def __init__(self,path):
        self.path=str(path);Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path) as c:c.executescript("""
        CREATE TABLE IF NOT EXISTS evidence_tasks(
          task_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,pack_id TEXT NOT NULL,artifact_id TEXT NOT NULL,
          title TEXT NOT NULL,priority TEXT NOT NULL,status TEXT NOT NULL,assignee TEXT,
          created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL,reason TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS uq_task ON evidence_tasks(case_id,pack_id,artifact_id);
        """)
    def create_from_pack(self,case_id,pack_id,workspace):
        assessment=assess_pack(get_pack(pack_id),Path(workspace))
        made=[]
        with sqlite3.connect(self.path) as c:
            for a in assessment["artifacts"]:
                good=a.get("quality") in ("VALIDATED","CORRELATED","AUTHORITATIVE")
                if a["status"]=="present" and good:continue
                tid=f"TASK-{uuid.uuid4().hex}";now=utc()
                status="VALIDATION_REQUIRED" if a["status"]=="present" else "REQUESTED"
                reason=a.get("rationale")
                if a["status"]=="present":
                    reason=(reason or "")+f" Present artifact quality={a.get('quality')}; v1.1 requires validated evidence."
                c.execute("""INSERT OR IGNORE INTO evidence_tasks VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                          (tid,case_id,pack_id,a["id"],a["title"],a["priority"],status,None,now,now,reason))
                if c.total_changes:made.append(tid)
        return made
    def update(self,task_id,status,assignee=None,reason=None):
        if status not in {"REQUESTED","VALIDATION_REQUIRED","COLLECTING","COLLECTED","UNAVAILABLE","WAIVED"}:raise ValueError(status)
        with sqlite3.connect(self.path) as c:
            c.execute("UPDATE evidence_tasks SET status=?,assignee=COALESCE(?,assignee),reason=COALESCE(?,reason),updated_utc=? WHERE task_id=?",
                      (status,assignee,reason,utc(),task_id))
    def list(self,case_id):
        with sqlite3.connect(self.path) as c:
            c.row_factory=sqlite3.Row;return [dict(x) for x in c.execute("SELECT * FROM evidence_tasks WHERE case_id=? ORDER BY priority,created_utc",(case_id,))]
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--db",required=True);ap.add_argument("--case-id",required=True);ap.add_argument("--pack",required=True);ap.add_argument("--workspace",required=True)
    a=ap.parse_args();db=TaskDB(a.db);print(json.dumps({"created":db.create_from_pack(a.case_id,a.pack,a.workspace),"tasks":db.list(a.case_id)},indent=2))
if __name__=="__main__":main()
