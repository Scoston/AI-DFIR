#!/usr/bin/env python3
"""Inventory installed dependency license metadata for release review."""
from __future__ import annotations
import argparse,json,re
from importlib import metadata
from pathlib import Path

REQ_FILES=['requirements.txt','requirements-model.txt','requirements-enterprise.txt','requirements-pdf-agpl.txt']

def names(root):
    out=[]
    for rel in REQ_FILES:
        p=root/rel
        if not p.exists():continue
        for line in p.read_text().splitlines():
            line=line.strip()
            if not line or line.startswith(('#','-r')):continue
            name=re.split(r'[<>=!~\[; ]', line, maxsplit=1)[0].strip()
            if name and name.lower() not in {x.lower() for x in out}:out.append(name)
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',default=str(Path(__file__).resolve().parents[1]));ap.add_argument('--out')
    a=ap.parse_args();root=Path(a.root);rows=[]
    for name in names(root):
        try:
            d=metadata.distribution(name);m=d.metadata
            lic=(m.get('License-Expression') or m.get('License') or '').strip()
            rows.append({'package':name,'installed':True,'version':d.version,'license':lic,'home_page':m.get('Home-page') or m.get('Project-URL')})
        except metadata.PackageNotFoundError:
            rows.append({'package':name,'installed':False,'version':None,'license':'VERIFY_UPSTREAM','home_page':None})
    obj={'schema':'ai-dfir/dependency-license-inventory/v1.6','dependencies':rows,
         'warning':'Review exact upstream license files for the versions distributed. PyMuPDF is intentionally optional because its AGPL/commercial terms differ from the project license.'}
    txt=json.dumps(obj,indent=2,sort_keys=True);Path(a.out).write_text(txt) if a.out else print(txt)
if __name__=='__main__':main()
