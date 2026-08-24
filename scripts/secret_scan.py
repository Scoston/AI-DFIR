#!/usr/bin/env python3
"""Conservative repository secret-pattern scan for release candidates."""
from __future__ import annotations
import argparse,re
from pathlib import Path
PATTERNS={
 'private_key':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
 'aws_access_key':re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
 'github_token':re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{30,}\b'),
 'slack_token':re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
 'long_bearer':re.compile(r'\bBearer\s+[A-Za-z0-9._~+/=-]{40,}\b',re.I),
}
SKIP={'.git','.venv','__pycache__','tests/fixtures'}
TEXT_EXT={'.py','.md','.txt','.json','.jsonl','.yaml','.yml','.toml','.ini','.cfg','.sql','.sh','.ps1','.cff'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('root',nargs='?',default='.');a=ap.parse_args();root=Path(a.root).resolve();hits=[]
 for p in root.rglob('*'):
  if not p.is_file():continue
  rel=str(p.relative_to(root)).replace('\\','/')
  if any(rel==x or rel.startswith(x.rstrip('/')+'/') for x in SKIP):continue
  if p.suffix.lower() not in TEXT_EXT and p.name not in {'LICENSE','NOTICE','Makefile'}:continue
  try:text=p.read_text(encoding='utf-8',errors='strict')
  except Exception:continue
  for name,pat in PATTERNS.items():
   for m in pat.finditer(text):hits.append({'file':rel,'type':name,'line':text.count('\n',0,m.start())+1})
 if hits:
  for h in hits:print(f"{h['file']}:{h['line']}: potential {h['type']}")
  raise SystemExit(2)
 print('Secret scan: PASS')
if __name__=='__main__':main()
