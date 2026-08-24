#!/usr/bin/env python3
"""Metadata/task capacity benchmark for AI-DFIR v1.5.

Uses SQLite when no DSN is supplied for reference CI tests. Production
readiness requires a benchmark generated against the deployment PostgreSQL
backend, not the SQLite reference result.
"""
from __future__ import annotations
import argparse,json,tempfile,time,uuid
from pathlib import Path
from enterprise_metadata_store import MetadataStore

def _run_store(s,count,tenant,case):
    s.ensure_tenant(tenant);s.create_case(tenant,case,'Scale')
    t0=time.perf_counter()
    for i in range(count):s.put_evidence(tenant,case,f'{i:064x}'[-64:],i+1,f'cas://{i}',metadata={'i':i})
    write_s=time.perf_counter()-t0;t1=time.perf_counter();rows=s.list_evidence(tenant,case);read_s=time.perf_counter()-t1
    return {'schema':'ai-dfir/scale-benchmark/v1.5','backend':s.kind,'records':count,'write_seconds':round(write_s,4),'read_seconds':round(read_s,4),
            'write_records_per_sec':round(count/max(write_s,.0001),1),'read_records_per_sec':round(count/max(read_s,.0001),1),
            'write_ops_per_sec':round(count/max(write_s,.0001),1),'read_ops_per_sec':round(count/max(read_s,.0001),1),'verified_records':len(rows)}
def run(count=5000,dsn=None):
    if dsn:
        s=MetadataStore(dsn);o=_run_store(s,count,'BENCH-'+uuid.uuid4().hex[:8],'CASE-'+uuid.uuid4().hex[:8]);o['deployment_benchmark']=s.kind=='postgres';return o
    with tempfile.TemporaryDirectory() as td:
        s=MetadataStore('sqlite:///'+str(Path(td)/'bench.db'));o=_run_store(s,count,'BENCH','CASE');o['deployment_benchmark']=False;o['note']='Reference-only. Production readiness requires a PostgreSQL deployment benchmark.';return o
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--count',type=int,default=5000);ap.add_argument('--dsn');ap.add_argument('--out');a=ap.parse_args();o=run(a.count,a.dsn);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
