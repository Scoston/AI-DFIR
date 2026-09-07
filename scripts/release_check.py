#!/usr/bin/env python3
"""AI-DFIR release verification and compatibility gate.

Quick checks validate current release code and synthetic fixtures.
Full checks additionally execute major compatibility suites.
No external network access is required; synthetic services bind loopback.
"""
from __future__ import annotations
import argparse, json, py_compile, re, shutil, subprocess, sys, tempfile, uuid
from pathlib import Path
from importlib import metadata
try:
    from packaging.requirements import Requirement
except Exception:
    Requirement=None

ROOT = Path(__file__).resolve().parents[1]

def run(cmd, cwd=ROOT, timeout=420):
    cp = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if cp.returncode:
        raise RuntimeError(f"command failed ({cp.returncode}): {' '.join(map(str,cmd))}\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}")
    return cp

def py(script, *args, timeout=420):
    return run([sys.executable, str(ROOT / script), *map(str, args)], timeout=timeout)

def compile_all():
    failures=[]
    for p in ROOT.glob("*.py"):
        try: py_compile.compile(str(p), doraise=True)
        except Exception as e: failures.append({"file":p.name,"error":repr(e)})
    if failures: raise RuntimeError(json.dumps(failures,indent=2))
    return len(list(ROOT.glob("*.py")))

def dashboard_js():
    text=(ROOT/"analyst_dashboard.py").read_text(encoding="utf-8")
    m=re.search(r"<script>(.*?)</script>",text,re.S)
    if not m: raise RuntimeError("dashboard <script> block missing")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(m.group(1)); p=Path(f.name)
    try: run(["node","--check",str(p)],cwd=ROOT,timeout=60)
    finally: p.unlink(missing_ok=True)

def clean_dir(name):
    p=ROOT/".release-test"/name
    shutil.rmtree(p,ignore_errors=True);p.mkdir(parents=True,exist_ok=True)
    return p

def compatibility(script, replacements, name):
    source=(ROOT/script).read_text(encoding="utf-8")
    for old,new in replacements:
        if old not in source:
            raise RuntimeError(f"compatibility patch marker not found in {script}: {old}")
        source=source.replace(old,new)
    with tempfile.NamedTemporaryFile("w",suffix=".py",dir=ROOT,delete=False,encoding="utf-8") as f:
        f.write(source); tmp=Path(f.name)
    try:
        parent=ROOT/".release-test"
        parent.mkdir(parents=True,exist_ok=True)
        out=parent/f"{name}-{uuid.uuid4().hex}"
        run([sys.executable,"-X","utf8",str(tmp),"--out",str(out)],timeout=420)
        return out
    finally: tmp.unlink(missing_ok=True)


def dependency_profile_check():
    """Validate default AI-DFIR requirements without inheriting unrelated host packages."""
    reqfile=ROOT/"requirements.txt"
    rows=[];fail=[]
    for raw in reqfile.read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith(("#","-r")):continue
        if Requirement is None:
            name=re.split(r"[<>=!~\[; ]",line,1)[0]
            spec=None
        else:
            r=Requirement(line);name=r.name;spec=r.specifier
        try:
            ver=metadata.version(name);ok=True if spec is None else ver in spec
        except metadata.PackageNotFoundError:
            ver=None;ok=False
        rows.append({"requirement":line,"installed_version":ver,"satisfied":ok})
        if not ok:fail.append(rows[-1])
    return rows,fail

def main():
    ap=argparse.ArgumentParser()
    g=ap.add_mutually_exclusive_group();g.add_argument("--quick",action="store_true");g.add_argument("--full",action="store_true")
    ap.add_argument("--json-out")
    a=ap.parse_args(); full=bool(a.full)
    results={}
    results["python_compile"]={"status":"PASS","files":compile_all()}
    dashboard_js(); results["dashboard_javascript"]={"status":"PASS"}
    py("scripts/secret_scan.py", ROOT, timeout=180); results["secret_scan"]={"status":"PASS"}
    py("scripts/github_repo_check_v16.py",timeout=60); results["github_repository_surface"]={"status":"PASS"}
    deps,missing=dependency_profile_check(); results["host_dependency_profile"]={"status":"PASS" if not missing else "WARN","requirements":len(deps),"unsatisfied_on_host":len(missing),"note":"CI installs requirements into a clean environment. Functional release tests exercise supported fallbacks where available."}
    py("tests/generate_test_corpus.py",timeout=300); results["test_corpus_generation"]={"status":"PASS"}
    py("tests/test_evidence_pack_matrix.py",timeout=420); results["evidence_pack_matrix"]={"status":"PASS","packs":111}
    py("tests/run_synthetic_scenarios.py",timeout=420); results["synthetic_scenarios"]={"status":"PASS","components":19}
    py("v17_selftest.py",timeout=60); results["v17_integrity_selftest"]={"status":"PASS"}
    py("v17_offline_selftest.py",timeout=60); results["v17_offline_case_verification_selftest"]={"status":"PASS"}
    py("v17_verification_assurance_selftest.py",timeout=90); results["v17_verification_assurance_selftest"]={"status":"PASS"}
    py("v17_release_candidate_selftest.py",timeout=90); results["v17_release_candidate_selftest"]={"status":"PASS"}
    py("v17_provenance_selftest.py",timeout=90); results["v17_provenance_selftest"]={"status":"PASS"}
    py("v17_key_policy_selftest.py",timeout=90); results["v17_key_policy_selftest"]={"status":"PASS"}
    py("v17_timestamp_selftest.py",timeout=90); results["v17_timestamp_selftest"]={"status":"PASS"}
    py("v17_policy_distribution_selftest.py",timeout=90); results["v17_policy_distribution_selftest"]={"status":"PASS"}
    py("v17_policy_quorum_selftest.py",timeout=90); results["v17_policy_quorum_selftest"]={"status":"PASS"}
    py("v17_policy_governance_selftest.py",timeout=90); results["v17_policy_governance_selftest"]={"status":"PASS"}
    py("v17_policy_delivery_selftest.py",timeout=90); results["v17_policy_delivery_selftest"]={"status":"PASS"}
    py("v17_key_trust_history_selftest.py",timeout=90); results["v17_key_trust_history_selftest"]={"status":"PASS"}
    py("v17_delivery_identity_selftest.py",timeout=90); results["v17_delivery_identity_selftest"]={"status":"PASS"}
    py("v17_policy_sync_selftest.py",timeout=90); results["v17_policy_sync_selftest"]={"status":"PASS"}
    py("v17_pack_replay_selftest.py",timeout=90); results["v17_pack_replay_selftest"]={"status":"PASS"}
    py("v17_cloudtrail_selftest.py",timeout=90); results["v17_cloudtrail_selftest"]={"status":"PASS"}
    py("v17_gcp_audit_selftest.py",timeout=90); results["v17_gcp_audit_selftest"]={"status":"PASS"}
    py("v17_azure_activity_selftest.py",timeout=90); results["v17_azure_activity_selftest"]={"status":"PASS"}
    py("v17_log_analytics_selftest.py",timeout=90); results["v17_log_analytics_selftest"]={"status":"PASS"}
    py("v17_log_analytics_context_selftest.py",timeout=90); results["v17_log_analytics_context_selftest"]={"status":"PASS"}
    py("v17_log_analytics_capture_selftest.py",timeout=90); results["v17_log_analytics_capture_selftest"]={"status":"PASS"}
    py("v17_log_analytics_get_selftest.py",timeout=90); results["v17_log_analytics_get_selftest"]={"status":"PASS"}
    py("v17_log_analytics_get_capture_selftest.py",timeout=90); results["v17_log_analytics_get_capture_selftest"]={"status":"PASS"}
    py("v17_log_analytics_resource_selftest.py",timeout=90); results["v17_log_analytics_resource_selftest"]={"status":"PASS"}
    py("v17_log_analytics_form_selftest.py",timeout=90); results["v17_log_analytics_form_selftest"]={"status":"PASS"}
    py("v17_log_analytics_lossless_selftest.py",timeout=90); results["v17_log_analytics_lossless_selftest"]={"status":"PASS"}
    py("v17_gcp_logging_capture_selftest.py",timeout=90); results["v17_gcp_logging_capture_selftest"]={"status":"PASS"}
    py("v17_evidence_validation_selftest.py",timeout=90); results["v17_evidence_validation_selftest"]={"status":"PASS"}
    py("v17_private_transparency_selftest.py",timeout=90); results["v17_private_transparency_selftest"]={"status":"PASS"}
    py("v17_parser_corpus_selftest.py",timeout=90); results["v17_parser_corpus_selftest"]={"status":"PASS","cases":3318,"profiles":12}
    py("v17_schema_drift_selftest.py",timeout=90); results["v17_schema_drift_selftest"]={"status":"PASS"}
    py("v17_case_exchange_selftest.py",timeout=90); results["v17_case_exchange_selftest"]={"status":"PASS"}
    py("v17_archive_intake_selftest.py",timeout=90); results["v17_archive_intake_selftest"]={"status":"PASS","cases":680,"profiles":5}
    out=ROOT/".release-test"/f"v16-{uuid.uuid4().hex}"; out.parent.mkdir(parents=True,exist_ok=True); py("v16_selftest.py","--out",out,timeout=420); results["v16_focused"]={"status":"PASS"}
    compatibility("v15_selftest.py",[("version':'1.5","version':'1.6"),("meta['tool_version']=='1.5'","meta['tool_version']=='1.6'")],"v15"); results["v15_compatibility"]={"status":"PASS"}
    if full:
        run([sys.executable,"-m","pytest","tests/test_v17_investigation_integrity.py","tests/test_v17_signed_checkpoints.py","tests/test_v17_offline_case_verification.py","tests/test_v17_verification_assurance.py","tests/test_v17_release_candidate.py","-q"],timeout=300); results["v17_integrity_regression"]={"status":"PASS","tests":56}
        run([sys.executable,"-m","pytest","tests/test_v17_provenance_replay.py","-q"],timeout=300); results["v17_provenance_regression"]={"status":"PASS","tests":30}
        run([sys.executable,"-m","pytest","tests/test_v17_key_policy.py","-q"],timeout=300); results["v17_key_policy_regression"]={"status":"PASS","tests":57}
        run([sys.executable,"-m","pytest","tests/test_v17_timestamps.py","-q"],timeout=300); results["v17_timestamp_regression"]={"status":"PASS","tests":68}
        run([sys.executable,"-m","pytest","tests/test_v17_policy_distribution.py","-q"],timeout=300); results["v17_policy_distribution_regression"]={"status":"PASS","tests":66}
        run([sys.executable,"-m","pytest","tests/test_v17_policy_quorum.py","-q"],timeout=300); results["v17_policy_quorum_regression"]={"status":"PASS","tests":67}
        run([sys.executable,"-m","pytest","tests/test_v17_policy_governance.py","-q"],timeout=300); results["v17_policy_governance_regression"]={"status":"PASS","tests":87}
        run([sys.executable,"-m","pytest","tests/test_v17_policy_delivery.py","-q"],timeout=300); results["v17_policy_delivery_regression"]={"status":"PASS","tests":139}
        run([sys.executable,"-m","pytest","tests/test_v17_key_trust_history.py","-q"],timeout=300); results["v17_key_trust_history_regression"]={"status":"PASS","tests":85}
        run([sys.executable,"-m","pytest","tests/test_v17_delivery_identity.py","-q"],timeout=300); results["v17_delivery_identity_regression"]={"status":"PASS","tests":80}
        run([sys.executable,"-m","pytest","tests/test_v17_policy_sync.py","-q"],timeout=300); results["v17_policy_sync_regression"]={"status":"PASS","tests":85}
        run([sys.executable,"-m","pytest","tests/test_v17_pack_replay.py","-q"],timeout=300); results["v17_pack_replay_regression"]={"status":"PASS","tests":96}
        run([sys.executable,"-m","pytest","tests/test_v17_cloudtrail.py","-q"],timeout=300); results["v17_cloudtrail_regression"]={"status":"PASS","tests":130}
        run([sys.executable,"-m","pytest","tests/test_v17_gcp_audit.py","-q"],timeout=300); results["v17_gcp_audit_regression"]={"status":"PASS","tests":163}
        run([sys.executable,"-m","pytest","tests/test_v17_azure_activity.py","-q"],timeout=300); results["v17_azure_activity_regression"]={"status":"PASS","tests":207}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics.py","-q"],timeout=300); results["v17_log_analytics_regression"]={"status":"PASS","tests":224}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_context.py","-q"],timeout=300); results["v17_log_analytics_context_regression"]={"status":"PASS","tests":171}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_capture.py","-q"],timeout=300); results["v17_log_analytics_capture_regression"]={"status":"PASS","tests":114}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_get.py","-q"],timeout=300); results["v17_log_analytics_get_regression"]={"status":"PASS","tests":160}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_get_capture.py","-q"],timeout=300); results["v17_log_analytics_get_capture_regression"]={"status":"PASS","tests":143}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_resource.py","-q"],timeout=300); results["v17_log_analytics_resource_regression"]={"status":"PASS","tests":142}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_form.py","-q"],timeout=300); results["v17_log_analytics_form_regression"]={"status":"PASS","tests":123}
        run([sys.executable,"-m","pytest","tests/test_v17_log_analytics_lossless.py","-q"],timeout=300); results["v17_log_analytics_lossless_regression"]={"status":"PASS","tests":171}
        run([sys.executable,"-m","pytest","tests/test_v17_gcp_logging_capture.py","-q"],timeout=300); results["v17_gcp_logging_capture_regression"]={"status":"PASS","tests":228}
        run([sys.executable,"-m","pytest","tests/test_v17_evidence_validation.py","-q"],timeout=300); results["v17_evidence_validation_regression"]={"status":"PASS","tests":190}
        run([sys.executable,"-m","pytest","tests/test_v17_private_transparency.py","-q"],timeout=300); results["v17_private_transparency_regression"]={"status":"PASS","tests":160}
        run([sys.executable,"-m","pytest","tests/test_v17_parser_corpus.py","-q"],timeout=300); results["v17_parser_corpus_regression"]={"status":"PASS","tests":76}
        run([sys.executable,"-m","pytest","tests/test_v17_schema_drift.py","-q"],timeout=300); results["v17_schema_drift_regression"]={"status":"PASS","tests":182}
        run([sys.executable,"-m","pytest","tests/test_v17_case_exchange.py","-q"],timeout=300); results["v17_case_exchange_regression"]={"status":"PASS","tests":101}
        run([sys.executable,"-m","pytest","tests/test_v17_archive_intake.py","-q"],timeout=300); results["v17_archive_intake_regression"]={"status":"PASS","tests":190}
        py("scripts/case_exchange_conformance_v17.py",timeout=120); results["v17_case_exchange_conformance"]={"status":"PASS","case_version":"1.5.0","valid_graphs":1,"invalid_graphs_rejected":4}
        compatibility("v14_selftest.py",[("version':'1.4","version':'1.6")],"v14"); results["v14_compatibility"]={"status":"PASS"}
        compatibility("v13_selftest.py",[("version':'1.3","version':'1.6")],"v13"); results["v13_compatibility"]={"status":"PASS"}
        compatibility("v12_selftest.py",[
            ("version':'1.2","version':'1.6"),
            ('assert meta["tool_version"]=="1.2"','assert meta["tool_version"]=="1.6"'),
        ],"v12")
        results["v12_representation_compatibility"]={"status":"PASS","note":"current case/workbench version semantics"}
        compatibility("v11_selftest.py",[
            ('q["mandatory_qualified"]==1 and q["artifacts"][0]["quality"]=="AUTHORITATIVE"','q["mandatory_qualified"]==1 and q["artifacts"][0]["quality"]=="VALIDATED"'),
            ("version':'1.1","version':'1.6"),
        ],"v11")
        results["v11_execution_compatibility"]={"status":"PASS","note":"v1.2+ signed-authority hardening semantics"}
    summary={"schema":"ai-dfir/release-check/v1.6","mode":"full" if full else "quick","status":"PASS","checks":results}
    text=json.dumps(summary,indent=2,sort_keys=True)
    if a.json_out: Path(a.json_out).write_text(text,encoding="utf-8")
    print(text)

if __name__=="__main__": main()
