#!/usr/bin/env python3
import argparse,json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def registry():return json.loads((HERE/'provider_adapters.json').read_text())
def find(name):
    n=name.lower();rows=[]
    for a in registry()['adapters']:
        if n in a['id'].lower() or any(n in m.lower() or m.lower() in n for m in a.get('models',[])):rows.append(a)
    return rows
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--model');a=ap.parse_args();print(json.dumps(find(a.model) if a.model else registry(),indent=2,sort_keys=True))
