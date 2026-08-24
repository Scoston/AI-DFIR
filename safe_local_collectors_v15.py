#!/usr/bin/env python3
"""Safe local collectors used by the distributed v1.5 worker.

They perform read-only filesystem/host introspection and never execute project
content. `filesystem_snapshot` hashes metadata/content but does not copy file
contents. `otel_export` copies one explicitly authorized telemetry export file.
"""
from __future__ import annotations
import hashlib,json,os,platform,shutil
from pathlib import Path

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
    return h.hexdigest()
def filesystem_snapshot(root,max_files=10000):
    root=Path(root).resolve();rows=[];gaps=[]
    if not root.exists():return {'schema':'ai-dfir/filesystem-snapshot/v1.5','root':str(root),'files':[],'gaps':[{'reason':'root_missing'}]}
    for p in sorted(root.rglob('*')):
        if len(rows)>=int(max_files):gaps.append({'reason':'max_files_reached','max_files':int(max_files)});break
        if not p.is_file() or p.is_symlink():continue
        try:rows.append({'path':str(p.relative_to(root)).replace('\\','/'),'size_bytes':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns,'sha256':sha(p)})
        except Exception as e:gaps.append({'path':str(p),'reason':'read_error','error':repr(e)})
    return {'schema':'ai-dfir/filesystem-snapshot/v1.5','root':str(root),'files':rows,'gaps':gaps,'count':len(rows),'content_copied':False}
def container_metadata():
    files={}
    for path in ('/proc/self/cgroup','/etc/os-release','/etc/hostname'):
        p=Path(path)
        if p.exists():files[path]=p.read_text(encoding='utf-8',errors='replace')[:65536]
    return {'schema':'ai-dfir/container-metadata/v1.5','platform':platform.platform(),'pid':os.getpid(),'uid':os.getuid() if hasattr(os,'getuid') else None,
            'environment_variable_names':sorted(os.environ.keys()),'host_files':files,'secret_values_collected':False}
def otel_export(src,out):
    src=Path(src).resolve();out=Path(out).resolve()
    if src.suffix.lower() not in ('.json','.jsonl','.ndjson'):raise ValueError('OTel export must be JSON/JSONL/NDJSON')
    out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,out)
    return {'schema':'ai-dfir/otel-export-acquisition/v1.5','source_path':str(src),'captured_path':str(out),'sha256':sha(out),'size_bytes':out.stat().st_size}
