#!/usr/bin/env python3
"""
Runtime/process/model inventory for AI-DFIR v0.4.

The standalone CLI captures system/process evidence. `capture_model_runtime(model)`
is intended to be imported into the already-running model worker so the actual
Python model object, registered hooks, adapters, devices, and config can be
inventoried.
"""
from __future__ import annotations
import argparse, hashlib, importlib.metadata, inspect, json, os, platform, socket, subprocess, sys
from pathlib import Path
from typing import Any, Dict
import torch


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":"), default=str).encode()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(8*1024*1024), b""):
            h.update(b)
    return h.hexdigest()


def callback_descriptor(cb):
    try:
        mod = getattr(cb, "__module__", None)
        qual = getattr(cb, "__qualname__", getattr(cb, "__name__", type(cb).__name__))
        src = inspect.getsourcefile(cb)
    except Exception:
        mod, qual, src = None, type(cb).__name__, None
    d = {
        "module": mod,
        "qualname": qual,
        "repr_sha256": sha256_bytes(repr(cb).encode()),
        "source_file": src,
    }
    if src and Path(src).is_file():
        try: d["source_sha256"] = sha256_file(Path(src))
        except Exception: pass
    return d


def hook_inventory(model):
    rows=[]
    for name,module in model.named_modules():
        for attr,kind in [
            ("_forward_pre_hooks","forward_pre"),
            ("_forward_hooks","forward"),
            ("_backward_hooks","backward"),
        ]:
            hooks=getattr(module, attr, {}) or {}
            for hid,cb in hooks.items():
                rows.append({
                    "module_name":name,
                    "module_class":f"{module.__class__.__module__}.{module.__class__.__qualname__}",
                    "hook_kind":kind,
                    "hook_id":str(hid),
                    "callback":callback_descriptor(cb),
                })
    return rows


def adapter_inventory(model):
    result={"active_adapters":None,"peft_configs":[],"model_class":model.__class__.__name__}
    try:
        active=getattr(model,"active_adapters",None)
        if callable(active): active=active()
        if active is not None:
            if isinstance(active,(str,int,float,bool)): result["active_adapters"]=active
            else: result["active_adapters"]=list(active)
    except Exception as e:
        result["active_adapters_error"]=repr(e)
    try:
        pc=getattr(model,"peft_config",None)
        if isinstance(pc,dict):
            for name,cfg in pc.items():
                try:
                    cdict=cfg.to_dict() if hasattr(cfg,"to_dict") else vars(cfg)
                except Exception:
                    cdict={"repr_sha256":sha256_bytes(repr(cfg).encode())}
                result["peft_configs"].append({
                    "name":str(name),
                    "config_sha256":sha256_bytes(canonical(cdict)),
                    "config":cdict,
                })
    except Exception as e:
        result["peft_config_error"]=repr(e)
    return result


def loaded_ai_modules():
    prefixes=("torch","transformers","peft","accelerate","safetensors","vllm")
    out=[]
    seen=set()
    for name,mod in sorted(sys.modules.items()):
        if not name.startswith(prefixes):
            continue
        path=getattr(mod,"__file__",None)
        if not path or path in seen:
            continue
        seen.add(path)
        row={"module":name,"path":path}
        p=Path(path)
        if p.is_file():
            try: row["sha256"]=sha256_file(p)
            except Exception: pass
        out.append(row)
    return out


def capture_model_runtime(model, model_ref=None, revision=None):
    try:
        cfg=model.config.to_dict()
    except Exception:
        cfg={"repr":repr(getattr(model,"config",None))}
    dtypes={}
    devices={}
    total=0
    for p in model.parameters():
        total += p.numel()
        dtypes[str(p.dtype)]=dtypes.get(str(p.dtype),0)+p.numel()
        devices[str(p.device)]=devices.get(str(p.device),0)+p.numel()
    stacks=[]
    for name,module in model.named_modules():
        if isinstance(module,torch.nn.ModuleList):
            stacks.append({"name":name,"length":len(module)})
    return {
        "schema":"ai-dfir/model-runtime-inventory/v0.4",
        "model_ref":model_ref,
        "revision":revision,
        "model_class":f"{model.__class__.__module__}.{model.__class__.__qualname__}",
        "config_sha256":sha256_bytes(canonical(cfg)),
        "config":cfg,
        "parameter_count":total,
        "parameter_dtypes":dtypes,
        "parameter_devices":devices,
        "module_lists":stacks,
        "hooks":hook_inventory(model),
        "adapters":adapter_inventory(model),
        "loaded_ai_python_modules":loaded_ai_modules(),
    }


def system_inventory():
    packages={}
    for n in ["torch","transformers","peft","accelerate","safetensors","vllm"]:
        try: packages[n]=importlib.metadata.version(n)
        except Exception: packages[n]=None
    env_names=sorted(os.environ.keys())  # names only; don't leak secrets
    cmd_hash=None
    try: cmd_hash=sha256_file(Path("/proc/self/cmdline"))
    except Exception: pass
    nvidia=None
    try:
        cp=subprocess.run(
            ["nvidia-smi","--query-gpu=index,uuid,name,driver_version,memory.total","--format=csv,noheader"],
            text=True,capture_output=True,timeout=10
        )
        if cp.returncode==0: nvidia=cp.stdout.strip().splitlines()
    except Exception: pass
    cgroup=None
    try: cgroup=Path("/proc/self/cgroup").read_text()
    except Exception: pass
    return {
        "schema":"ai-dfir/system-runtime-inventory/v0.4",
        "pid":os.getpid(),
        "hostname":socket.gethostname(),
        "platform":platform.platform(),
        "python":sys.version,
        "packages":packages,
        "environment_variable_names":env_names,
        "process_cmdline_sha256":cmd_hash,
        "nvidia_gpus":nvidia,
        "cgroup":cgroup,
    }


def compare(a,b):
    findings=[]
    if a.get("config_sha256") != b.get("config_sha256"):
        findings.append({"type":"model_config_changed","approved":a.get("config_sha256"),"suspect":b.get("config_sha256")})
    ah={(x["module_name"],x["hook_kind"],x["callback"].get("source_sha256"),x["callback"].get("qualname")) for x in a.get("hooks",[])}
    bh={(x["module_name"],x["hook_kind"],x["callback"].get("source_sha256"),x["callback"].get("qualname")) for x in b.get("hooks",[])}
    for x in sorted(bh-ah,key=str):
        findings.append({"type":"unexpected_hook","hook":x})
    for x in sorted(ah-bh,key=str):
        findings.append({"type":"missing_approved_hook","hook":x})
    aa=a.get("adapters",{}).get("active_adapters")
    ba=b.get("adapters",{}).get("active_adapters")
    if aa != ba:
        findings.append({"type":"active_adapters_changed","approved":aa,"suspect":ba})
    ap={x["name"]:x.get("config_sha256") for x in a.get("adapters",{}).get("peft_configs",[])}
    bp={x["name"]:x.get("config_sha256") for x in b.get("adapters",{}).get("peft_configs",[])}
    for name in sorted(set(bp)-set(ap)):
        findings.append({"type":"unexpected_adapter_config","name":name,"sha256":bp[name]})
    for name in sorted(set(ap)&set(bp)):
        if ap[name]!=bp[name]:
            findings.append({"type":"adapter_config_changed","name":name,"approved":ap[name],"suspect":bp[name]})
    return findings


def selftest(out):
    class M(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.layers=torch.nn.ModuleList([torch.nn.Linear(4,4),torch.nn.Linear(4,4)])
            class C:
                def to_dict(self): return {"hidden_size":4}
            self.config=C()
        def forward(self,x):
            for l in self.layers:x=l(x)
            return x
    m=M()
    approved=capture_model_runtime(m,"toy","1")
    def observer(mod,inp,out): return None
    h=m.layers[1].register_forward_hook(observer)
    suspect=capture_model_runtime(m,"toy","1")
    findings=compare(approved,suspect)
    h.remove()
    if not any(x["type"]=="unexpected_hook" for x in findings):
        raise RuntimeError("selftest failed to detect hook")
    p=Path(out);p.mkdir(parents=True,exist_ok=True)
    (p/"approved.json").write_text(json.dumps(approved,indent=2,default=str))
    (p/"suspect.json").write_text(json.dumps(suspect,indent=2,default=str))
    (p/"findings.json").write_text(json.dumps(findings,indent=2,default=str))
    print(json.dumps({"status":"PASS","findings":len(findings)},indent=2))


def main():
    ap=argparse.ArgumentParser()
    sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("system");p.add_argument("--out",required=True)
    p=sp.add_parser("compare");p.add_argument("--approved",required=True);p.add_argument("--suspect",required=True);p.add_argument("--out",required=True)
    p=sp.add_parser("selftest");p.add_argument("--out",required=True)
    args=ap.parse_args()
    if args.cmd=="system":
        Path(args.out).write_text(json.dumps(system_inventory(),indent=2,sort_keys=True))
    elif args.cmd=="compare":
        a=json.loads(Path(args.approved).read_text());b=json.loads(Path(args.suspect).read_text())
        f=compare(a,b);Path(args.out).write_text(json.dumps(f,indent=2,default=str));print(json.dumps(f,indent=2,default=str))
    else:selftest(args.out)

if __name__=="__main__":main()
