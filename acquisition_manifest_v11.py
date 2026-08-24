#!/usr/bin/env python3
"""
Forensic acquisition manifest with metadata and clock-quality tracking.

No OCR or content interpretation. This records provenance and filesystem metadata.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, socket, stat
from datetime import datetime,timezone
from pathlib import Path

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(path,chunk=8*1024*1024):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(chunk),b""):h.update(b)
    return h.hexdigest()

def xattrs(path):
    out={}
    if hasattr(os,"listxattr"):
        try:
            for k in os.listxattr(path,follow_symlinks=False):
                try:
                    v=os.getxattr(path,k,follow_symlinks=False)
                    out[k]=hashlib.sha256(v).hexdigest()
                except Exception:out[k]="UNREADABLE"
        except Exception:pass
    return out

def describe(path,logical_name=None,source_type=None,source_host=None,source_user=None,
             clock_offset_ms=None,clock_uncertainty_ms=None,coverage_start=None,coverage_end=None,authoritative=False):
    p=Path(path);st=os.lstat(p)
    d={"logical_name":logical_name or p.name,"path":str(p.resolve()),"source_type":source_type,
       "host":source_host,"user":source_user,"coverage_start_utc":coverage_start,"coverage_end_utc":coverage_end,
       "authoritative":bool(authoritative),"clock_offset_ms":clock_offset_ms,
       "clock_uncertainty_ms":clock_uncertainty_ms,
       "mode_octal":oct(stat.S_IMODE(st.st_mode)),"uid":getattr(st,"st_uid",None),"gid":getattr(st,"st_gid",None),
       "inode":getattr(st,"st_ino",None),"device":getattr(st,"st_dev",None),
       "nlink":getattr(st,"st_nlink",None),"size":st.st_size,
       "mtime_ns":st.st_mtime_ns,"ctime_ns":st.st_ctime_ns,"atime_ns":st.st_atime_ns,
       "is_symlink":stat.S_ISLNK(st.st_mode),"xattrs_sha256":xattrs(p)}
    if d["is_symlink"]:
        d["symlink_target"]=os.readlink(p)
    elif p.is_file():
        d["sha256"]=sha(p)
    return d

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);ap.add_argument("--file",action="append",required=True,help="NAME=PATH")
    ap.add_argument("--source-type");ap.add_argument("--source-host");ap.add_argument("--source-user")
    ap.add_argument("--clock-offset-ms",type=float);ap.add_argument("--clock-uncertainty-ms",type=float)
    ap.add_argument("--coverage-start");ap.add_argument("--coverage-end");ap.add_argument("--authoritative",action="store_true")
    a=ap.parse_args();arts=[]
    for spec in a.file:
        name,path=spec.split("=",1)
        arts.append(describe(path,name,a.source_type,a.source_host,a.source_user,
                             a.clock_offset_ms,a.clock_uncertainty_ms,a.coverage_start,a.coverage_end,a.authoritative))
    obj={"schema":"ai-dfir/acquisition-manifest/v1.1","acquired_utc":utc(),"collector_host":socket.gethostname(),
         "platform":platform.platform(),"artifacts":arts,
         "clock_quality":{"offset_ms":a.clock_offset_ms,"uncertainty_ms":a.clock_uncertainty_ms,
                          "rule":"Ordering inside overlapping clock uncertainty intervals is not treated as definitive."}}
    Path(a.out).write_text(json.dumps(obj,indent=2,sort_keys=True));print(json.dumps(obj,indent=2,sort_keys=True))
if __name__=="__main__":main()
