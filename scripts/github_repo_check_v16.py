#!/usr/bin/env python3
"""Validate the repository surface expected for an AI-DFIR v1.6 GitHub publication."""
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[1]
required=[
 'README.md','LICENSE','NOTICE','LICENSE_GUIDE.md','THIRD_PARTY_NOTICES.md',
 'SECURITY.md','CONTRIBUTING.md','CODE_OF_CONDUCT.md','SUPPORT.md','GOVERNANCE.md','ROADMAP.md','CITATION.cff','AUTHORS.md',
 'INSTALL.md','TESTING.md','THREAT_MODEL.md','DATA_HANDLING.md','RELEASE_CHECKLIST.md','UPLOAD_CHECKLIST.md',
 'docs/README.md','docs/demo/README.md','docs/demo/DEMO_SCRIPT.md','docs/demo/AI-DFIR-v1.6.0-demo.mp4','scripts/generate_demo_case.py','scripts/make_demo_video.py',
 '.github/CODEOWNERS.example','.github/PULL_REQUEST_TEMPLATE.md','.github/dependabot.yml',
 '.github/ISSUE_TEMPLATE/bug_report.yml','.github/ISSUE_TEMPLATE/feature_request.yml','.github/ISSUE_TEMPLATE/config.yml',
 '.github/workflows/ci.yml','.github/workflows/full-regression.yml','.github/workflows/codeql.yml',
 '.github/workflows/dependency-review.yml','.github/workflows/scorecard.yml','.github/workflows/release.yml',
 '.github/workflows/container.yml','.github/workflows/docs-check.yml'
]
missing=[x for x in required if not (ROOT/x).exists()]
findings=[]

# Do not ship an active fake CODEOWNERS file.
active=ROOT/'.github/CODEOWNERS'
if active.exists():
    txt=active.read_text(encoding='utf-8',errors='replace')
    if re.search(r'@(?:OWNER|your-github|REPLACE|example)',txt,re.I):
        findings.append('active .github/CODEOWNERS contains unresolved example owner')

critical={
 'README.md':ROOT/'README.md',
 'UPLOAD_CHECKLIST.md':ROOT/'UPLOAD_CHECKLIST.md',
 'SECURITY.md':ROOT/'SECURITY.md',
 'TESTING.md':ROOT/'TESTING.md',
 'docs/reference/GITHUB_RELEASE_GUIDE.md':ROOT/'docs/reference/GITHUB_RELEASE_GUIDE.md',
 'docs/reference/TEST_SCENARIO_CATALOG.md':ROOT/'docs/reference/TEST_SCENARIO_CATALOG.md',
}
for name,path in critical.items():
    text=path.read_text(encoding='utf-8',errors='replace')
    if name in ('README.md','UPLOAD_CHECKLIST.md','SECURITY.md','TESTING.md') and re.search(r'AI-DFIR v1\.5|v1\.5\.0|\| 1\.5\.x \| Yes',text):
        findings.append(f'{name}: stale current-release v1.5 reference')

# Issue-template config contact links must be absolute URLs if present.
config=(ROOT/'.github/ISSUE_TEMPLATE/config.yml').read_text(encoding='utf-8')
for m in re.finditer(r'^\s*url:\s*(\S+)',config,re.M):
    if not m.group(1).startswith(('https://','http://')):
        findings.append('.github/ISSUE_TEMPLATE/config.yml contains non-absolute contact URL')

# Detect clearly unsafe/stale GitHub action majors that are no longer the project baseline.
for wf in (ROOT/'.github/workflows').glob('*.yml'):
    text=wf.read_text(encoding='utf-8',errors='replace')
    if re.search(r'actions/checkout@v[1-6]\b',text):
        findings.append(str(wf.relative_to(ROOT))+': checkout older than v7')
    if 'github/codeql-action/' in text and re.search(r'github/codeql-action/[^@]+@v[1-3]\b',text):
        findings.append(str(wf.relative_to(ROOT))+': CodeQL action older than v4')

# Verify local Markdown links in repository documentation.
link_re=re.compile(r'\[[^\]]*\]\(([^)]+)\)')
for md in ROOT.rglob('*.md'):
    if any(x in md.parts for x in ('.release-test','tests','__pycache__')):continue
    text=md.read_text(encoding='utf-8',errors='replace')
    for target in link_re.findall(text):
        target=target.strip()
        if not target or target.startswith(('http://','https://','mailto:','#','sandbox:')):continue
        local=target.split('#',1)[0]
        if not local:continue
        if not (md.parent/local).resolve().exists():
            findings.append(f'{md.relative_to(ROOT)}: broken local link {target}')

if missing or findings:
    print({'status':'FAIL','missing':missing,'findings':findings});sys.exit(2)
print({'status':'PASS','required_files':len(required),'workflows':len(list((ROOT/'.github/workflows').glob('*.yml'))),'active_codeowners':active.exists()})
