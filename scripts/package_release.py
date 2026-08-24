#!/usr/bin/env python3
"""Build an AI-DFIR v1.6 GitHub release after full offline verification."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, sys, tarfile, tempfile, zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION="1.6.0"
NAME=f"AI-DFIR-v{VERSION}"
EXCLUDES={"__pycache__",".release-test",".git",".venv"}

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(8*1024*1024),b""):h.update(b)
    return h.hexdigest()
def included_files(root):
    for p in sorted(root.rglob("*")):
        if not p.is_file():continue
        rel=p.relative_to(root)
        if any(x in EXCLUDES for x in rel.parts):continue
        if rel.name=="PACKAGE_MANIFEST_V1.6.json":continue
        yield p,rel
def run_check(root, full=True, json_out=None):
    cmd=[sys.executable,str(root/"scripts/release_check.py"),"--full" if full else "--quick"]
    if json_out:cmd += ["--json-out",str(json_out)]
    cp=subprocess.run(cmd,cwd=root,text=True,capture_output=True,timeout=900)
    if cp.returncode:raise RuntimeError(f"release check failed\n{cp.stdout}\n{cp.stderr}")
    return cp.stdout
def manifest():
    rows=[]
    for p,rel in included_files(ROOT):rows.append({"path":str(rel).replace(os.sep,"/"),"size":p.stat().st_size,"sha256":sha(p)})
    return {"schema":"ai-dfir/package-manifest/v1.6","package":"AI-DFIR","version":VERSION,"created_utc":utc(),"file_count":len(rows),"evidence_pack_count":len(list((ROOT/"evidence_packs").rglob("*.json"))),"files":rows,"note":"Manifest intentionally excludes itself to avoid recursive self-hashing."}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out-dir",default="/mnt/data/AI-DFIR-v1.6.0-release");ap.add_argument("--skip-source-check",action="store_true");a=ap.parse_args()
    out=Path(a.out_dir).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)
    source_result=out/"SOURCE_RELEASE_CHECK.json"
    if not a.skip_source_check:run_check(ROOT,True,source_result)
    else:source_result.write_text(json.dumps({"schema":"ai-dfir/release-check/v1.6","status":"SKIPPED_ALREADY_RUN_IN_CI"},indent=2))
    subprocess.run([sys.executable,str(ROOT/"scripts/license_inventory.py"),"--root",str(ROOT),"--out",str(ROOT/"DEPENDENCY_LICENSE_INVENTORY.json")],check=True,cwd=ROOT)
    subprocess.run([sys.executable,str(ROOT/"scripts/generate_sbom.py"),"--root",str(ROOT),"--out",str(ROOT/"SBOM_CYCLONEDX_1.7.json")],check=True,cwd=ROOT)
    man=manifest();(ROOT/"PACKAGE_MANIFEST_V1.6.json").write_text(json.dumps(man,indent=2,sort_keys=True),encoding="utf-8")
    zip_path=out/f"{NAME}.zip";tar_path=out/f"{NAME}.tar.gz"
    with zipfile.ZipFile(zip_path,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
        for p,rel in sorted([(x,x.relative_to(ROOT)) for x in ROOT.rglob("*") if x.is_file() and not any(y in EXCLUDES for y in x.relative_to(ROOT).parts)]):
            z.write(p,arcname=str(Path(NAME)/rel))
    with tarfile.open(tar_path,"w:gz") as t:
        for p in sorted(ROOT.rglob("*")):
            if p.is_file() and not any(y in EXCLUDES for y in p.relative_to(ROOT).parts):t.add(p,arcname=str(Path(NAME)/p.relative_to(ROOT)),recursive=False)
    # Clean-room test exact ZIP contents.
    with tempfile.TemporaryDirectory(prefix="aidfir-v16-extracted-") as td:
        td=Path(td)
        with zipfile.ZipFile(zip_path) as z:z.extractall(td)
        extracted=td/NAME
        extract_result=out/"EXTRACTED_RELEASE_CHECK.json"
        run_check(extracted,True,extract_result)
    # Release assets.
    for rel in ["LICENSE","NOTICE","RELEASE_NOTES_V1.6.md","V1.6_RUNBOOK.md","SBOM_CYCLONEDX_1.7.json","DEPENDENCY_LICENSE_INVENTORY.json","PACKAGE_MANIFEST_V1.6.json","V1.6_SELFTEST_RESULT.txt","PRODUCTION_ASSURANCE_IMPLEMENTATION_MATRIX_V1.6.md","SOURCES_V1.6.md"]:
        if (ROOT/rel).exists():shutil.copy2(ROOT/rel,out/rel)
    demo_video=ROOT/"docs/demo/AI-DFIR-v1.6.0-demo.mp4"
    if demo_video.exists():shutil.copy2(demo_video,out/demo_video.name)
    # Documentation and synthetic test-corpus handoff assets.
    docs_zip=out/f"{NAME}-Documentation.zip"
    with zipfile.ZipFile(docs_zip,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
        for base in [ROOT/"docs",ROOT]:
            if base==ROOT:
                names=["README.md","INSTALL.md","SECURITY.md","THREAT_MODEL.md","DATA_HANDLING.md","V1.6_RUNBOOK.md","PRODUCTION_READINESS_V1.6.md","PLATFORM_ASSURANCE_V1.6.md","HUMAN_IN_THE_LOOP_PRODUCTION_V1.6.md","RELEASE_NOTES_V1.6.md","GITHUB_PRODUCTION_GUIDE_V1.6.md","PRODUCTION_ASSURANCE_IMPLEMENTATION_MATRIX_V1.6.md","SOURCES_V1.6.md"]
                for n in names:
                    p=ROOT/n
                    if p.exists():z.write(p,arcname=str(Path(NAME)/n))
            else:
                for p in sorted(base.rglob("*")):
                    if p.is_file():z.write(p,arcname=str(Path(NAME)/p.relative_to(ROOT)))
    tests_zip=out/f"{NAME}-Test-Corpus.zip"
    with zipfile.ZipFile(tests_zip,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
        for p in sorted((ROOT/"tests/fixtures").rglob("*")):
            if p.is_file():z.write(p,arcname=str(Path(NAME)/p.relative_to(ROOT)))
    sums=[]
    for p in sorted(out.iterdir()):
        if p.is_file() and p.name!="SHA256SUMS":sums.append(f"{sha(p)}  {p.name}")
    (out/"SHA256SUMS").write_text("\n".join(sums)+"\n",encoding="utf-8")
    validation={"schema":"ai-dfir/release-validation/v1.6","status":"PASS","version":VERSION,"validated_utc":utc(),"source_check":"PASS","extracted_zip_check":"PASS","zip_sha256":sha(zip_path),"tar_gz_sha256":sha(tar_path),"evidence_packs":man["evidence_pack_count"],"manifest_files":man["file_count"]}
    (out/"RELEASE_VALIDATION_V1.6.json").write_text(json.dumps(validation,indent=2,sort_keys=True),encoding="utf-8")
    # Final outer bundle for GitHub/admin handoff.
    bundle=Path(str(out)+"-UPLOAD-BUNDLE.zip")
    bundle.unlink(missing_ok=True)
    with zipfile.ZipFile(bundle,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
        for p in sorted(out.iterdir()):
            if p.is_file():z.write(p,arcname=str(Path(out.name)/p.name))
    print(json.dumps({**validation,"release_dir":str(out),"upload_bundle":str(bundle),"upload_bundle_sha256":sha(bundle)},indent=2,sort_keys=True))

if __name__=="__main__":main()
