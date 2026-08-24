#!/usr/bin/env python3
"""Append-only hash/HMAC chained containment audit log."""
from __future__ import annotations
import hashlib, hmac, json, os
from datetime import datetime, timezone
from pathlib import Path


def utc_now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def canon(o): return json.dumps(o,sort_keys=True,separators=(",",":")).encode()


class ContainmentAudit:
    def __init__(self,path,key=None):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        self.key=key
        self.prev="0"*64
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip(): self.prev=json.loads(line)["event_hash"]

    def add(self,event_type,incident_id,**details):
        core={
            "schema":"ai-dfir/containment-audit/v0.6",
            "timestamp_utc":utc_now(),
            "event_type":event_type,
            "incident_id":incident_id,
            "details":details,
            "prev_event_hash":self.prev,
        }
        eh=hashlib.sha256(canon(core)).hexdigest()
        obj={**core,"event_hash":eh}
        if self.key:
            obj["event_hmac_sha256"]=hmac.new(self.key,bytes.fromhex(eh),hashlib.sha256).hexdigest()
        with self.path.open("a",encoding="utf-8") as f:
            f.write(json.dumps(obj,sort_keys=True)+"\n");f.flush();os.fsync(f.fileno())
        self.prev=eh
        return obj
