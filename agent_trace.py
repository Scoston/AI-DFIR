#!/usr/bin/env python3
"""
Hash-first agent/tool/retrieval/consequence trace for AI-DFIR.

The log intentionally stores content hashes by default. It can preserve the
sequence and authority context without automatically collecting sensitive prompt
or tool payload plaintext.
"""
import argparse, hashlib, json, os, time, uuid
from datetime import datetime, timezone
from pathlib import Path


def utc(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def canon(o): return json.dumps(o,sort_keys=True,separators=(",",":")).encode()


class Trace:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        self.prev="0"*64
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip(): self.prev=json.loads(line)["event_hash"]
    def add(self,event):
        core=dict(event);core["prev_event_hash"]=self.prev
        h=hashlib.sha256(canon(core)).hexdigest();core["event_hash"]=h
        with self.path.open("a") as f:
            f.write(json.dumps(core,sort_keys=True)+"\n");f.flush();os.fsync(f.fileno())
        self.prev=h;return core


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--log",required=True)
    ap.add_argument("--inference-id",required=True)
    ap.add_argument("--type",required=True,choices=["decision","retrieval","tool_call","tool_result","delegation","consequence","containment"])
    ap.add_argument("--name",default=None)
    ap.add_argument("--content",default=None,help="Content to HASH; plaintext is not stored")
    ap.add_argument("--content-hash",default=None)
    ap.add_argument("--authority-id",default=None)
    ap.add_argument("--parent-id",default=None)
    ap.add_argument("--metadata-json",default=None)
    args=ap.parse_args()
    ch=args.content_hash or (sha(args.content) if args.content is not None else None)
    meta=json.loads(args.metadata_json) if args.metadata_json else {}
    event={
        "schema":"ai-dfir/agent-trace/v0.4",
        "event_id":str(uuid.uuid4()),
        "timestamp_utc":utc(),
        "monotonic_ns":time.monotonic_ns(),
        "inference_id":args.inference_id,
        "event_type":args.type,
        "name":args.name,
        "content_sha256":ch,
        "authority_id":args.authority_id,
        "parent_id":args.parent_id,
        "metadata":meta,
    }
    print(json.dumps(Trace(args.log).add(event),indent=2,sort_keys=True))

if __name__=="__main__":main()
