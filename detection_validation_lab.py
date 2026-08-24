#!/usr/bin/env python3
"""Manifest-driven defensive regression harness. No arbitrary shell commands."""
from __future__ import annotations
import argparse,json,subprocess,sys,tempfile
from pathlib import Path

ALLOWED_PREFIXES=('python','python3')

def collect_types(obj):
    out=[]
    if isinstance(obj,dict):
        if obj.get('type'):out.append(obj['type'])
        for v in obj.values():out+=collect_types(v)
    elif isinstance(obj,list):
        for v in obj:out+=collect_types(v)
    return out

def run_suite(suite,root):
    results=[];tp=fp=fn=0
    root=Path(root).resolve()
    for t in suite.get('tests',[]):
        script=(root/t['script']).resolve()
        if root not in script.parents or not script.exists():raise ValueError('test script outside package or missing')
        with tempfile.TemporaryDirectory(prefix='aidfir-val-') as td:
            out=Path(td)/'result.json';args=[sys.executable,str(script)]
            for a in t.get('args',[]):args.append(str(a).replace('{OUT}',str(out)).replace('{ROOT}',str(root)))
            cp=subprocess.run(args,capture_output=True,text=True,timeout=int(t.get('timeout_seconds',60)),cwd=root)
            parsed={}
            if out.exists():
                try:parsed=json.loads(out.read_text())
                except Exception:parsed={}
            found=set(collect_types(parsed));expected=set(t.get('expected_signals') or []);forbidden=set(t.get('forbidden_signals') or [])
            missing=sorted(expected-found);unexpected=sorted(forbidden&found);passed=cp.returncode in set(t.get('allowed_returncodes',[0])) and not missing and not unexpected
            tp+=len(expected&found);fn+=len(missing);fp+=len(unexpected)
            results.append({'id':t['id'],'passed':passed,'returncode':cp.returncode,'expected_signals':sorted(expected),'found_signals':sorted(found),'missing':missing,'forbidden_present':unexpected,'stderr_tail':cp.stderr[-1000:]})
    precision=tp/(tp+fp) if tp+fp else 1.0;recall=tp/(tp+fn) if tp+fn else 1.0
    return {'schema':'ai-dfir/detection-validation/v1.4','status':'PASS' if all(x['passed'] for x in results) else 'FAIL','tests':results,'metrics':{'true_positive_expectations':tp,'false_positive_forbidden':fp,'false_negative_missing':fn,'precision_proxy':round(precision,4),'recall_proxy':round(recall,4)}}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--suite',required=True);ap.add_argument('--package-root',required=True);ap.add_argument('--out')
    a=ap.parse_args();o=run_suite(json.loads(Path(a.suite).read_text()),a.package_root);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['status']=='PASS' else 2)
if __name__=='__main__':main()
