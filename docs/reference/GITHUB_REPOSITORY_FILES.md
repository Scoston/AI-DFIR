# GitHub Repository File Guide

AI-DFIR ships the standard public-project governance and security files expected for a serious defensive-security repository.

| File | Purpose |
|---|---|
| `README.md` | landing page, architecture, quick start |
| `LICENSE` | Apache License 2.0 project license |
| `NOTICE` | project notice and third-party boundary |
| `LICENSE_GUIDE.md` | project/optional dependency licensing guidance |
| `THIRD_PARTY_NOTICES.md` | dependency license review inventory |
| `SECURITY.md` | private vulnerability reporting and supported versions |
| `CONTRIBUTING.md` | contribution/testing/security expectations |
| `CODE_OF_CONDUCT.md` | community conduct |
| `SUPPORT.md` | support boundaries |
| `GOVERNANCE.md` | project governance |
| `ROADMAP.md` | planned work and non-goals |
| `CITATION.cff` | research citation metadata |
| `RELEASE_CHECKLIST.md` | maintainer release process |
| `UPLOAD_CHECKLIST.md` | exact GitHub release/upload checklist |
| `.github/ISSUE_TEMPLATE/` | structured bug/feature requests |
| `.github/PULL_REQUEST_TEMPLATE.md` | review checklist |
| `.github/dependabot.yml` | dependency update automation |
| `.github/workflows/ci.yml` | synthetic/release checks |
| `.github/workflows/codeql.yml` | CodeQL analysis |
| `.github/workflows/dependency-review.yml` | dependency review |
| `.github/workflows/scorecard.yml` | OpenSSF Scorecard |

Security vulnerabilities should follow `SECURITY.md`, not public issue templates.
