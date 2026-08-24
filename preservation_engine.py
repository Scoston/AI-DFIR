#!/usr/bin/env python3
"""
Pre/post-containment forensic preservation.

Design:
- copy small volatile/config evidence into a case directory
- acquire runtime process evidence before containment when PID is supplied
- hash every copied/acquired artifact
- create an investigator-signed provenance bundle/seal
- avoid copying huge model checkpoints by default; preserve their existing
  cryptographic manifests and paths instead
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def sha256_file(path: Path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(8*1024*1024),b""):
            h.update(b)
    return h.hexdigest()


def safe_name(s):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def parse_named(values):
    out=[]
    for spec in values or []:
        if "=" not in spec:
            raise ValueError(f"Expected NAME=PATH: {spec}")
        name,raw=spec.split("=",1)
        p=Path(raw)
        if not p.exists():
            raise FileNotFoundError(p)
        out.append((name,p))
    return out


def copy_item(name,src,dst_root):
    target=dst_root/safe_name(name)
    if src.is_dir():
        shutil.copytree(src,target,dirs_exist_ok=True,symlinks=True)
    else:
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(src,target,follow_symlinks=False)
    return target


def describe(path: Path, base: Path):
    if path.is_file():
        return {
            "path":str(path.relative_to(base)),
            "kind":"file",
            "size":path.stat().st_size,
            "sha256":sha256_file(path),
        }
    files=[]
    for p in sorted(path.rglob("*")):
        if p.is_file():
            files.append({
                "path":str(p.relative_to(base)),
                "size":p.stat().st_size,
                "sha256":sha256_file(p),
            })
    tree=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {
        "path":str(path.relative_to(base)),
        "kind":"directory",
        "tree_sha256":tree,
        "file_count":len(files),
        "files":files,
    }


def preserve(case_dir: Path, incident_id: str, phase: str, copy_specs,
             reference_specs, pid=None, signing_key=None, model_path=None,
             runtime_collector=True):
    phase_dir=case_dir/f"{phase}_preservation"
    if phase_dir.exists():
        raise FileExistsError(f"Preservation directory already exists: {phase_dir}")
    evidence=phase_dir/"evidence"
    evidence.mkdir(parents=True)
    started=utc_now()

    copied=[]
    for name,src in parse_named(copy_specs):
        copied.append((name,copy_item(name,src,evidence/"copied")))

    runtime_dir=None
    if pid is not None and runtime_collector:
        runtime_dir=evidence/"runtime"
        cmd=["bash",str(HERE/"collect_runtime_linux.sh"),
             "--pid",str(pid),"--out",str(runtime_dir)]
        cp=subprocess.run(cmd,text=True,capture_output=True)
        (phase_dir/"runtime_collector.stdout.txt").write_text(cp.stdout or "")
        (phase_dir/"runtime_collector.stderr.txt").write_text(cp.stderr or "")
        if cp.returncode != 0:
            raise RuntimeError(f"runtime collector failed rc={cp.returncode}")

    refs=[]
    for name,p in parse_named(reference_specs):
        desc={
            "name":name,
            "path":str(p.resolve()),
            "kind":"directory" if p.is_dir() else "file",
        }
        if p.is_file():
            desc["sha256"]=sha256_file(p)
            desc["size"]=p.stat().st_size
        else:
            # Reference directories are not recursively hashed here to avoid
            # unexpectedly reading huge checkpoints. Supply a manifest file
            # when cryptographic model identity is required.
            desc["note"]="directory referenced in place; provide cryptographic manifest separately"
        refs.append(desc)

    if model_path:
        refs.append({
            "name":"model_path",
            "path":str(Path(model_path).resolve()),
            "kind":"reference",
            "note":"Model checkpoint not copied by preservation engine.",
        })

    artifacts=[]
    for name,p in copied:
        artifacts.append({"name":name,**describe(p,phase_dir)})
    if runtime_dir and runtime_dir.exists():
        artifacts.append({"name":"runtime",**describe(runtime_dir,phase_dir)})

    manifest={
        "schema":"ai-dfir/preservation-manifest/v0.6",
        "incident_id":incident_id,
        "phase":phase,
        "started_utc":started,
        "completed_utc":utc_now(),
        "pid":pid,
        "artifacts":artifacts,
        "references":refs,
    }
    manifest_path=phase_dir/"preservation_manifest.json"
    manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True))

    # Seal with the existing v0.4 provenance bundle.
    if signing_key:
        bundle_dir=phase_dir/"signed_seal"
        cmd=[sys.executable,str(HERE/"provenance_bundle.py"),"bundle",
             "--case-id",incident_id,
             "--inference-id",f"{incident_id}-{phase}",
             "--private-key",str(signing_key),
             "--artifact",f"preservation_manifest={manifest_path}",
             "--artifact",f"evidence={evidence}",
             "--out",str(bundle_dir)]
        cp=subprocess.run(cmd,text=True,capture_output=True)
        (phase_dir/"seal.stdout.txt").write_text(cp.stdout or "")
        (phase_dir/"seal.stderr.txt").write_text(cp.stderr or "")
        if cp.returncode != 0:
            raise RuntimeError(f"provenance sealing failed rc={cp.returncode}")

    result={
        "incident_id":incident_id,
        "phase":phase,
        "phase_dir":str(phase_dir),
        "manifest":str(manifest_path),
        "manifest_sha256":sha256_file(manifest_path),
        "signed":bool(signing_key),
        "completed_utc":utc_now(),
    }
    (phase_dir/"PRESERVATION_COMPLETE.json").write_text(
        json.dumps(result,indent=2,sort_keys=True)
    )
    return result


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case-dir",required=True)
    ap.add_argument("--incident-id",required=True)
    ap.add_argument("--phase",required=True,choices=["pre","post","manual"])
    ap.add_argument("--copy",action="append",default=[],help="NAME=PATH")
    ap.add_argument("--reference",action="append",default=[],help="NAME=PATH")
    ap.add_argument("--pid",type=int)
    ap.add_argument("--signing-key")
    ap.add_argument("--model-path")
    ap.add_argument("--skip-runtime-collector",action="store_true")
    args=ap.parse_args()
    result=preserve(
        Path(args.case_dir),args.incident_id,args.phase,args.copy,args.reference,
        pid=args.pid,signing_key=Path(args.signing_key) if args.signing_key else None,
        model_path=args.model_path,runtime_collector=not args.skip_runtime_collector
    )
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
