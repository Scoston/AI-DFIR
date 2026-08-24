#!/usr/bin/env python3
"""Human-readable fleet status CLI."""
import argparse, json, urllib.request


def get(url):
    with urllib.request.urlopen(url,timeout=10) as r:
        return json.loads(r.read())


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--collector",default="http://127.0.0.1:8787")
    ap.add_argument("--json",action="store_true")
    args=ap.parse_args()
    obj=get(args.collector.rstrip("/")+"/v1/fleet")
    if args.json:
        print(json.dumps(obj,indent=2,sort_keys=True));return
    nodes=obj.get("nodes",[])
    print(f"{'NODE':24} {'STATE':12} {'SEQ':>8} {'AGE(s)':>10} FINDINGS")
    print("-"*88)
    for n in nodes:
        findings=",".join(x.get("code","") for x in n.get("findings",[])[:3])
        print(f"{n['node_id'][:24]:24} {n['state'][:12]:12} {str(n.get('last_seq','-')):>8} "
              f"{str(n.get('age_seconds','-')):>10} {findings}")


if __name__=="__main__":main()
