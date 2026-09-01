#!/usr/bin/env python3
"""Generate an offline CycloneDX 1.7 SBOM for AI-DFIR release review.

The SBOM is derived from repository requirement files and installed package
metadata when available. It intentionally does not contact package registries.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

REQ_FILES = [
    "requirements.txt",
    "requirements-model.txt",
    "requirements-enterprise.txt",
    "requirements-pdf-agpl.txt",
    "requirements-dev.txt",
]

def utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def parse_requirements(root: Path):
    deps = {}
    for rel in REQ_FILES:
        p = root / rel
        if not p.exists():
            continue
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-r"):
                continue
            name = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
            if not name:
                continue
            d = deps.setdefault(name.lower(), {"name": name, "requirements": [], "profiles": []})
            d["requirements"].append(line)
            d["profiles"].append(rel)
    return list(deps.values())

def dist_meta(name: str):
    try:
        d = metadata.distribution(name)
        m = d.metadata
        lic = (m.get("License-Expression") or m.get("License") or "").strip()
        refs = []
        for k, v in m.items():
            if k == "Project-URL" and v:
                parts = [x.strip() for x in v.split(",", 1)]
                refs.append(parts[-1])
        hp = m.get("Home-page")
        if hp:
            refs.append(hp)
        return d.version, lic or "NOASSERTION", list(dict.fromkeys(refs))
    except metadata.PackageNotFoundError:
        return None, "NOASSERTION", []

def component(dep):
    version, lic, refs = dist_meta(dep["name"])
    c = {
        "type": "library",
        "name": dep["name"],
        "version": version or "UNRESOLVED",
        "scope": "optional" if dep["profiles"] == ["requirements-pdf-agpl.txt"] else "required",
        "properties": [
            {"name": "ai-dfir:requirements", "value": " | ".join(sorted(set(dep["requirements"])))},
            {"name": "ai-dfir:profiles", "value": ",".join(sorted(set(dep["profiles"])))},
            {"name": "ai-dfir:installed_for_sbom", "value": str(version is not None).lower()},
        ],
        "licenses": [{"license": {"name": lic}}],
    }
    if refs:
        c["externalReferences"] = [{"type": "website", "url": u} for u in refs if u.startswith(("http://", "https://"))]
    return c

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--out", required=True)
    ap.add_argument("--app-version", default="1.6.0")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc[1-9][0-9]*)?", a.app_version):
        raise ValueError(f"invalid AI-DFIR application version: {a.app_version!r}")
    root = Path(a.root).resolve()
    deps = parse_requirements(root)
    comps = sorted((component(x) for x in deps), key=lambda x: x["name"].lower())
    serial_seed = json.dumps([(x["name"], x["version"]) for x in comps], separators=(",", ":"), sort_keys=True).encode()
    serial = hashlib.sha256(serial_seed).hexdigest()
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": utc(),
            "component": {"type": "application", "name": "AI-DFIR", "version": a.app_version},
            "properties": [
                {"name": "ai-dfir:sbom-generation", "value": "offline requirement/install metadata"},
                {"name": "ai-dfir:license-review", "value": "See LICENSE_GUIDE.md and THIRD_PARTY_NOTICES.md; upstream license files remain authoritative."},
            ],
        },
        "components": comps,
    }
    Path(a.out).write_text(json.dumps(sbom, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": "PASS", "components": len(comps), "out": str(Path(a.out).resolve()), "app_version": a.app_version}, indent=2))

if __name__ == "__main__":
    main()
