#!/usr/bin/env python3
"""
AI-DFIR v1.1 Evidence Quality Engine.

v0.8-v1.0 primarily answered: "Is a matching file present?"
v1.1 answers:
  - Is it authentic enough to use?
  - Is it intact?
  - Is it attributable to this case/host/user/agent?
  - Does it cover the incident window?
  - Is it complete and parseable?
  - Is it independently corroborated?

Quality states:
  MISSING < PRESENT_UNVALIDATED < VALIDATED < CORRELATED < AUTHORITATIVE

CONFLICTING is a separate warning state and never satisfies a conclusion gate.
"""
from __future__ import annotations
import argparse, csv, fnmatch, hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path

QUALITY_ORDER={
    "MISSING":0,
    "PRESENT_UNVALIDATED":1,
    "VALIDATED":2,
    "CORRELATED":3,
    "AUTHORITATIVE":4,
    "CONFLICTING":-1,
    "STALE":-1,
    "INCOMPLETE":-1,
}
DEFAULT_GATE_QUALITY="VALIDATED"

def sha256_file(path,chunk=8*1024*1024):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(chunk),b""): h.update(b)
    return h.hexdigest()

def parse_iso(s):
    if not s:return None
    try:return datetime.fromisoformat(str(s).replace("Z","+00:00"))
    except Exception:return None

def load_json(path,default=None):
    try:return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:return default

def case_context(case_root:Path):
    profile=load_json(case_root/"incident_profile.json",{}) or {}
    case=load_json(case_root/"case.json",{}) or {}
    acquisition=load_json(case_root/"ACQUISITION_MANIFEST.json",{}) or {}
    # Signed v1.2 manifests are DSSE-like envelopes. For assessment, the
    # verified payload may be copied to ACQUISITION_MANIFEST.json while
    # ACQUISITION_TRUST.json records signature/hash verification.
    trust=load_json(case_root/"ACQUISITION_TRUST.json",{}) or {}
    policy=load_json(case_root/"EVIDENCE_QUALITY_POLICY.json",{}) or {}
    window=(profile.get("incident_window") or case.get("incident_window") or {})
    return {
        "profile":profile,
        "case":case,
        "acquisition":acquisition,
        "acquisition_trust":trust,
        "quality_policy":policy,
        "incident_start":parse_iso(window.get("start_utc")),
        "incident_end":parse_iso(window.get("end_utc")),
        "expected_host":profile.get("host") or case.get("host"),
        "expected_user":profile.get("user") or case.get("user"),
        "expected_agent":profile.get("agent"),
    }

def relative_files(root:Path):
    rows=[]
    for p in sorted(root.rglob("*")):
        if p.is_file():
            try:rel=str(p.relative_to(root)).replace("\\","/")
            except Exception:rel=str(p)
            rows.append((p,rel))
    return rows

def artifact_matches(root:Path,artifact):
    pats=artifact.get("presence_patterns") or []
    out=[]
    for p,rel in relative_files(root):
        if any(fnmatch.fnmatch(rel.lower(),pat.lower()) or fnmatch.fnmatch(p.name.lower(),pat.lower()) for pat in pats):
            out.append((p,rel))
    return out

def acquisition_entry(ctx,rel):
    acq=ctx.get("acquisition") or {}
    entries=list(acq.get("artifacts",[]) or acq.get("files",[]) or [])
    exact=[]
    basename=[]
    for e in entries:
        paths={str(e.get("relative_path") or ""),str(e.get("path") or ""),str(e.get("logical_name") or "")}
        if rel in paths: exact.append(e)
        elif Path(rel).name in {Path(x).name for x in paths if x}: basename.append(e)
    if len(exact)==1:return exact[0]
    if len(exact)>1:return {"_ambiguous":True,"_reason":"multiple exact acquisition entries"}
    if len(basename)==1:return basename[0]
    if len(basename)>1:return {"_ambiguous":True,"_reason":"ambiguous basename acquisition match"}
    return {}


def semantic_validate(path:Path,artifact,validation):
    findings=[];ok=True
    size=path.stat().st_size
    min_size=int(validation.get("min_size_bytes",1))
    if size < min_size:
        ok=False;findings.append(f"size {size} < minimum {min_size}")
    max_size=validation.get("max_size_bytes")
    if max_size is not None and size>int(max_size):
        ok=False;findings.append(f"size {size} > maximum {max_size}")

    fmt=validation.get("format")
    if not fmt:
        ext=path.suffix.lower()
        fmt={".json":"json",".jsonl":"jsonl",".csv":"csv"}.get(ext,"binary")
    parsed=None
    try:
        if fmt=="json":
            parsed=json.loads(path.read_text(encoding="utf-8"))
        elif fmt=="jsonl":
            parsed=[]
            for i,line in enumerate(path.read_text(encoding="utf-8",errors="strict").splitlines(),1):
                if line.strip(): parsed.append(json.loads(line))
            if validation.get("require_records",False) and not parsed:
                ok=False;findings.append("JSONL has no records")
        elif fmt=="csv":
            with path.open(newline="",encoding="utf-8") as f:
                parsed=list(csv.DictReader(f))
            if validation.get("require_records",False) and not parsed:
                ok=False;findings.append("CSV has no records")
        elif fmt=="text":
            parsed=path.read_text(encoding="utf-8",errors="strict")
    except Exception as e:
        ok=False;findings.append(f"parse failure: {e!r}")

    fields=validation.get("must_contain_fields") or []
    if fields and parsed is not None:
        samples=[]
        if isinstance(parsed,dict):samples=[parsed]
        elif isinstance(parsed,list):samples=[x for x in parsed[:100] if isinstance(x,dict)]
        missing=[f for f in fields if not any(f in x for x in samples)]
        if missing:
            ok=False;findings.append("required fields absent: "+", ".join(missing))

    needles=validation.get("must_contain_text") or []
    if needles:
        try:text=path.read_text(encoding="utf-8",errors="replace")
        except Exception:text=""
        missing=[x for x in needles if x not in text]
        if missing:
            ok=False;findings.append("required text absent: "+", ".join(missing))

    return ok,findings,fmt

def time_validate(path:Path,ctx,entry,validation):
    findings=[];ok=True
    start=ctx.get("incident_start");end=ctx.get("incident_end")
    if not start and not end:return True,findings
    # Prefer acquisition-record time coverage. Fall back to file mtime only as a weak signal.
    cov_start=parse_iso(entry.get("coverage_start_utc") or entry.get("start_utc"))
    cov_end=parse_iso(entry.get("coverage_end_utc") or entry.get("end_utc"))
    if cov_start or cov_end:
        if start and cov_end and cov_end < start:
            ok=False;findings.append("artifact coverage ends before incident window")
        if end and cov_start and cov_start > end:
            ok=False;findings.append("artifact coverage starts after incident window")
        if validation.get("must_cover_entire_window"):
            if start and (not cov_start or cov_start>start):
                ok=False;findings.append("artifact does not cover incident start")
            if end and (not cov_end or cov_end<end):
                ok=False;findings.append("artifact does not cover incident end")
    elif validation.get("require_time_attribution",False):
        ok=False;findings.append("no acquisition time coverage metadata")
    return ok,findings

def attribution_validate(ctx,entry,validation):
    findings=[];ok=True
    expected={
        "host":ctx.get("expected_host"),
        "user":ctx.get("expected_user"),
        "agent":ctx.get("expected_agent"),
    }
    for k,v in expected.items():
        if not v:continue
        got=entry.get(k) or entry.get(f"source_{k}")
        if got is None and validation.get("require_attribution",False):
            ok=False;findings.append(f"{k} attribution missing")
        elif got is not None and str(got).lower()!=str(v).lower():
            ok=False;findings.append(f"{k} attribution mismatch: {got!r} != {v!r}")
    return ok,findings

def integrity_validate(path:Path,entry,validation,artifact=None,ctx=None):
    findings=[];ok=True;digest=sha256_file(path)
    if entry.get("_ambiguous"):
        ok=False;findings.append(entry.get("_reason","ambiguous acquisition binding"))
    expected=entry.get("sha256") or validation.get("expected_sha256")
    if expected and digest.lower()!=str(expected).lower():
        ok=False;findings.append("SHA-256 mismatch against acquisition/expected value")
    policy=(ctx or {}).get("quality_policy") or {}
    strict=policy.get("strict_mandatory_hash",True)
    mandatory=(artifact or {}).get("priority")=="mandatory"
    allow_unhashed=validation.get("allow_unhashed",False)
    require_hash=validation.get("require_acquisition_hash",False) or (strict and mandatory and not allow_unhashed)
    if require_hash and not expected:
        ok=False;findings.append("acquisition SHA-256 missing")
    return ok,findings,digest

def assess_match(path:Path,rel:str,artifact,ctx):
    validation=artifact.get("validation") or {}
    entry=acquisition_entry(ctx,rel)
    reasons=[]
    sem_ok,sem,fmt=semantic_validate(path,artifact,validation);reasons+=sem
    time_ok,tm=time_validate(path,ctx,entry,validation);reasons+=tm
    attr_ok,at=attribution_validate(ctx,entry,validation);reasons+=at
    int_ok,integ,digest=integrity_validate(path,entry,validation,artifact,ctx);reasons+=integ
    validated=sem_ok and time_ok and attr_ok and int_ok

    quality="VALIDATED" if validated else "PRESENT_UNVALIDATED"
    trust=ctx.get("acquisition_trust") or {}
    trusted_manifest=bool(trust.get("manifest_signature_verified") and trust.get("valid"))
    if entry.get("authoritative") is True and validated:
        if trusted_manifest:
            quality="AUTHORITATIVE"
        else:
            reasons.append("authoritative claim not promoted: signed acquisition trust not verified")
    elif entry.get("corroborated") is True and validated:
        if trusted_manifest:
            quality="CORRELATED"
        else:
            reasons.append("corroborated claim not promoted: signed acquisition trust not verified")

    # Explicit acquisition flags override upward scoring and surface conflict/staleness.
    if entry.get("conflicting") is True:quality="CONFLICTING"
    elif entry.get("stale") is True:quality="STALE"
    elif entry.get("incomplete") is True:quality="INCOMPLETE"

    return {
        "path":rel,"size":path.stat().st_size,"sha256":digest,"format":fmt,
        "quality":quality,"quality_score":QUALITY_ORDER[quality],
        "validated":validated,"findings":reasons,"acquisition":entry,
    }

def assess_artifact(case_root:Path,artifact,ctx=None):
    ctx=ctx or case_context(case_root)
    matches=artifact_matches(case_root,artifact)
    if not matches:
        return {**artifact,"status":"missing","quality":"MISSING","quality_score":0,
                "matches":[],"match_assessments":[]}
    rows=[assess_match(p,rel,artifact,ctx) for p,rel in matches]
    # Conflicting evidence is deliberately never allowed to win by numeric max.
    good=[x for x in rows if x["quality_score"]>=0]
    best=max(good,key=lambda x:x["quality_score"]) if good else rows[0]
    return {**artifact,"status":"present","quality":best["quality"],
            "quality_score":best["quality_score"],"matches":[x["path"] for x in rows],
            "match_assessments":rows}

def quality_satisfies(actual,required):
    if actual in ("CONFLICTING","STALE","INCOMPLETE"):return False
    return QUALITY_ORDER.get(actual,-1) >= QUALITY_ORDER.get(required,999)

def assess_pack(pack,case_root:Path):
    root=Path(case_root).resolve();ctx=case_context(root)
    rows=[assess_artifact(root,a,ctx) for a in pack.get("artifacts",[])]
    by={x["id"]:x for x in rows}
    mandatory=[x for x in rows if x.get("priority")=="mandatory"]
    required_quality=pack.get("mandatory_min_quality","VALIDATED")
    qualified=sum(1 for x in mandatory if quality_satisfies(x["quality"],required_quality))
    gates=[]
    for g in pack.get("conclusion_gates",[]):
        reqs=g.get("requires") or [];aliases=g.get("allow_aliases") or {}
        qmap=g.get("quality_requires") or {}
        missing=[];low=[]
        hits=0
        for rid in reqs:
            candidates=[rid]+list(aliases.get(rid,[]))
            rq=qmap.get(rid,g.get("min_quality",DEFAULT_GATE_QUALITY))
            satisfying=[c for c in candidates if c in by and quality_satisfies(by[c]["quality"],rq)]
            if satisfying:hits+=1
            else:
                if any(c in by and by[c]["quality"]!="MISSING" for c in candidates):
                    low.append({"artifact":rid,"required_quality":rq,
                                "actual":[by[c]["quality"] for c in candidates if c in by]})
                else:missing.append(rid)
        ok=(hits>0) if g.get("logic","all")=="any" else hits==len(reqs)
        gates.append({**g,"status":"supported" if ok else "not_supported",
                      "missing":missing,"insufficient_quality":low})
    return {
        "schema":"ai-dfir/evidence-quality-assessment/v1.2",
        "pack_id":pack["id"],"pack_title":pack["title"],"case_root":str(root),
        "mandatory_min_quality":required_quality,
        "mandatory_qualified":qualified,"mandatory_total":len(mandatory),
        "mandatory_percent":round((qualified/len(mandatory)*100) if mandatory else 100.0,1),
        "artifacts":rows,"conclusion_gates":gates,
        "quality_scale":QUALITY_ORDER,
        "rule":"Presence alone is insufficient. Mandatory evidence requires hash-bound acquisition by default; authoritative/correlated promotion requires verified signed acquisition trust.",
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--pack",required=True);ap.add_argument("--case",required=True);ap.add_argument("--out")
    a=ap.parse_args()
    # Import lazily to avoid a circular import when evidence_pack_engine delegates here.
    from evidence_pack_engine import get_pack
    obj=assess_pack(get_pack(a.pack),Path(a.case))
    txt=json.dumps(obj,indent=2,sort_keys=True)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)

if __name__=="__main__":main()
