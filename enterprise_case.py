#!/usr/bin/env python3
"""Enterprise case lifecycle and assignments."""
from __future__ import annotations
import argparse, json, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path

STATUSES=["OPEN","TRIAGE","INVESTIGATING","CONTAINED","RECOVERING","CLOSED","ARCHIVED"]
TRANSITIONS={
 "OPEN":{"TRIAGE","INVESTIGATING","CLOSED"},
 "TRIAGE":{"INVESTIGATING","CLOSED"},
 "INVESTIGATING":{"CONTAINED","RECOVERING","CLOSED"},
 "CONTAINED":{"INVESTIGATING","RECOVERING"},
 "RECOVERING":{"INVESTIGATING","CLOSED"},
 "CLOSED":{"INVESTIGATING","ARCHIVED"},
 "ARCHIVED":set(),
}

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

class CaseDB:
    def __init__(self,path):
        self.path=str(path);self.init()
    def conn(self):
        c=sqlite3.connect(self.path);c.row_factory=sqlite3.Row;return c
    def init(self):
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with self.conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS cases(
              case_id TEXT PRIMARY KEY,title TEXT NOT NULL,status TEXT NOT NULL,
              severity TEXT NOT NULL,tenant_id TEXT,owner TEXT,created_utc TEXT NOT NULL,
              updated_utc TEXT NOT NULL,summary TEXT,tags_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS case_members(
              case_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,
              added_utc TEXT NOT NULL,PRIMARY KEY(case_id,user_id)
            );
            CREATE TABLE IF NOT EXISTS case_events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,
              timestamp_utc TEXT NOT NULL,actor TEXT NOT NULL,event_type TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            """)
    def create(self,title,severity,actor,tenant_id=None,owner=None,summary=None,tags=None,case_id=None):
        cid=case_id or f"AIIR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        now=utc()
        with self.conn() as c:
            c.execute("INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (cid,title,"OPEN",severity,tenant_id,owner or actor,now,now,summary,json.dumps(tags or [])))
            c.execute("INSERT INTO case_members VALUES(?,?,?,?)",(cid,actor,"owner",now))
            c.execute("INSERT INTO case_events(case_id,timestamp_utc,actor,event_type,details_json) VALUES(?,?,?,?,?)",
                      (cid,now,actor,"case_created",json.dumps({"severity":severity,"title":title},sort_keys=True)))
        return cid
    def transition(self,cid,new_status,actor,reason):
        if new_status not in STATUSES:raise ValueError(new_status)
        with self.conn() as c:
            row=c.execute("SELECT status FROM cases WHERE case_id=?",(cid,)).fetchone()
            if not row:raise KeyError(cid)
            old=row["status"]
            if new_status not in TRANSITIONS[old]:
                raise ValueError(f"invalid transition {old}->{new_status}")
            now=utc()
            c.execute("UPDATE cases SET status=?,updated_utc=? WHERE case_id=?",(new_status,now,cid))
            c.execute("INSERT INTO case_events(case_id,timestamp_utc,actor,event_type,details_json) VALUES(?,?,?,?,?)",
                      (cid,now,actor,"case_transition",json.dumps({"from":old,"to":new_status,"reason":reason},sort_keys=True)))
    def assign(self,cid,user_id,member_role,actor):
        now=utc()
        with self.conn() as c:
            c.execute("""INSERT INTO case_members VALUES(?,?,?,?)
                         ON CONFLICT(case_id,user_id) DO UPDATE SET role=excluded.role,added_utc=excluded.added_utc""",
                      (cid,user_id,member_role,now))
            c.execute("INSERT INTO case_events(case_id,timestamp_utc,actor,event_type,details_json) VALUES(?,?,?,?,?)",
                      (cid,now,actor,"case_assignment",json.dumps({"user_id":user_id,"role":member_role},sort_keys=True)))
    def get(self,cid):
        with self.conn() as c:
            row=c.execute("SELECT * FROM cases WHERE case_id=?",(cid,)).fetchone()
            if not row:return None
            obj=dict(row);obj["tags"]=json.loads(obj.pop("tags_json"))
            obj["members"]=[dict(x) for x in c.execute("SELECT * FROM case_members WHERE case_id=? ORDER BY user_id",(cid,))]
            obj["events"]=[{**dict(x),"details":json.loads(x["details_json"])} for x in c.execute(
                "SELECT * FROM case_events WHERE case_id=? ORDER BY id",(cid,))]
            for e in obj["events"]:e.pop("details_json",None)
            return obj
    def list(self,tenant_id=None):
        q="SELECT * FROM cases";args=[]
        if tenant_id is not None:q+=" WHERE tenant_id=?";args=[tenant_id]
        q+=" ORDER BY updated_utc DESC"
        with self.conn() as c:return [dict(x) for x in c.execute(q,args)]

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    for n in ["create","transition","assign","show","list"]:sp.add_parser(n)
    args,rest=ap.parse_known_args()
    # CLI kept intentionally compact; production API calls CaseDB directly.
    print("Use enterprise_api.py or import CaseDB for v1.0 case operations.")

if __name__=="__main__":main()
