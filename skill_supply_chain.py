#!/usr/bin/env python3
"""Static agent-skill supply-chain manifest, signing, and drift analysis."""
from __future__ import annotations
import argparse,hashlib,json,re,os
from pathlib import Path
from urllib.parse import urlparse
from fleet_crypto import sign_payload,verify_envelope

TEXT_EXT={'.md','.txt','.json','.yaml','.yml','.toml','.py','.js','.ts','.sh','.ps1','.rb','.go','.rs','.java','.xml'}
EXEC_EXT={'.py','.js','.ts','.sh','.ps1','.exe','.dll','.so','.dylib','.jar','.wasm'}
URL_RE=re.compile(r'(?i)https?://[^\s\)\]\}\>\"\']+')
SENSITIVE=('~/.ssh','.ssh/','memory.md','claude.md','agents.md','credentials','token','secret','keyring','.aws/','.azure/','.config/gcloud')
CAP_WORDS={'network':['http://','https://','socket','websocket','requests.','fetch('],'shell':['subprocess','os.system','child_process','powershell','cmd.exe','bash -c'],'filesystem_write':['write_text','write_bytes','open(','fs.write','unlink','remove(','rename('],'credential_access':['credential','token','secret','.ssh','.aws','.azure'],'memory_write':['memory.md','memory_write','update_memory','upsert_memory']}

def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def merkle(leaves):
    nodes=[bytes.fromhex(x) for x in sorted(leaves)]
    if not nodes:return hashlib.sha256(b'').hexdigest()
    while len(nodes)>1:
        if len(nodes)%2:nodes.append(nodes[-1])
        nodes=[hashlib.sha256(nodes[i]+nodes[i+1]).digest() for i in range(0,len(nodes),2)]
    return nodes[0].hex()

def inspect_text(text):
    urls=sorted(set(URL_RE.findall(text)));caps=[]
    low=text.lower()
    for cap,needles in CAP_WORDS.items():
        if any(n.lower() in low for n in needles):caps.append(cap)
    sensitive=[x for x in SENSITIVE if x.lower() in low]
    return urls,sorted(caps),sensitive

def inventory(root):
    root=Path(root).resolve();files=[];all_urls=set();observed_caps=set();sensitive=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file():continue
        rel=str(p.relative_to(root)).replace('\\','/');item={'path':rel,'sha256':sha(p),'size':p.stat().st_size,'executable':os.access(p,os.X_OK) or p.suffix.lower() in EXEC_EXT}
        if p.suffix.lower() in TEXT_EXT and p.stat().st_size<=2*1024*1024:
            text=p.read_text(encoding='utf-8',errors='replace');urls,caps,sens=inspect_text(text)
            item['external_urls']=urls;item['observed_capability_signals']=caps;item['sensitive_path_signals']=sens
            all_urls.update(urls);observed_caps.update(caps)
            if sens:sensitive.append({'path':rel,'signals':sens})
        files.append(item)
    leaves=[hashlib.sha256((f['path']+'\0'+f['sha256']).encode()).hexdigest() for f in files]
    metadata={}
    for name in ('skill.json','manifest.json','package.json','pyproject.toml','requirements.txt','SKILL.md'):
        p=root/name
        if p.exists():metadata[name]={'sha256':sha(p),'size':p.stat().st_size}
    return {'schema':'ai-dfir/skill-manifest/v1.4','root':str(root),'file_count':len(files),'merkle_root':merkle(leaves),'files':files,'external_urls':sorted(all_urls),'observed_capability_signals':sorted(observed_caps),'sensitive_path_findings':sensitive,'metadata_files':metadata}

def diff(a,b):
    findings=[];aa={x['path']:x for x in a.get('files',[])};bb={x['path']:x for x in b.get('files',[])}
    for p in sorted(set(bb)-set(aa)):
        x=bb[p];findings.append({'type':'skill_file_added','severity':'critical' if x.get('executable') else 'high','file':x})
    for p in sorted(set(aa)&set(bb)):
        if aa[p]['sha256']!=bb[p]['sha256']:findings.append({'type':'skill_file_changed','severity':'critical' if bb[p].get('executable') else 'high','path':p,'approved_sha256':aa[p]['sha256'],'suspect_sha256':bb[p]['sha256']})
    for p in sorted(set(aa)-set(bb)):findings.append({'type':'skill_file_removed','severity':'medium','path':p})
    old_urls=set(a.get('external_urls') or []);new_urls=set(b.get('external_urls') or [])
    if new_urls-old_urls:findings.append({'type':'skill_external_instruction_or_endpoint_drift','severity':'critical','added_urls':sorted(new_urls-old_urls)})
    oldcap=set(a.get('observed_capability_signals') or []);newcap=set(b.get('observed_capability_signals') or [])
    if newcap-oldcap:findings.append({'type':'skill_capability_expansion','severity':'critical','added_capabilities':sorted(newcap-oldcap)})
    if b.get('sensitive_path_findings'):findings.append({'type':'skill_sensitive_identity_or_memory_access_signal','severity':'high','records':b['sensitive_path_findings'][:50]})
    return {'schema':'ai-dfir/skill-supply-chain-diff/v1.4','approved':a,'suspect':b,'findings':findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
    p=sp.add_parser('inventory');p.add_argument('--root',required=True);p.add_argument('--out')
    p=sp.add_parser('sign');p.add_argument('--manifest',required=True);p.add_argument('--private-key',required=True);p.add_argument('--out',required=True)
    p=sp.add_parser('verify');p.add_argument('--manifest',required=True);p.add_argument('--public-key',required=True)
    p=sp.add_parser('diff');p.add_argument('--approved',required=True);p.add_argument('--suspect',required=True);p.add_argument('--out')
    a=ap.parse_args()
    if a.cmd=='inventory':o=inventory(a.root)
    elif a.cmd=='sign':o=sign_payload(Path(a.private_key),json.loads(Path(a.manifest).read_text()));Path(a.out).write_text(json.dumps(o,indent=2,sort_keys=True))
    elif a.cmd=='verify':o={'valid':True,'payload':verify_envelope(Path(a.public_key),json.loads(Path(a.manifest).read_text()))}
    else:o=diff(json.loads(Path(a.approved).read_text()),json.loads(Path(a.suspect).read_text()))
    s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if getattr(a,'out',None) and a.cmd in ('inventory','diff') else print(s)
if __name__=='__main__':main()
