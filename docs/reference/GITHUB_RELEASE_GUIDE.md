# GitHub Publication Guide

Before creating the public repository:

1. create a new repository without auto-generating a second license/README;
2. upload the contents of the release source directory;
3. enable branch protection/rulesets for `main`;
4. require pull-request review and status checks;
5. enable private vulnerability reporting, Dependabot alerts/updates, secret
   scanning where available, CodeQL, and dependency review;
6. review GitHub Actions permissions and pin action versions/SHAs according to
   your organization policy;
7. enable GitHub Discussions if desired;
8. copy `.github/CODEOWNERS.example` to `.github/CODEOWNERS` only after the real maintainer usernames/teams are known;
9. create a signed/tagged `v1.6.0` release;
10. upload the ZIP, TAR.GZ, `SHA256SUMS`, package manifest, SBOM/license inventory,
    and release validation report.

The repository includes community files, issue templates, Dependabot, CI,
CodeQL, dependency-review, and OpenSSF Scorecard workflow templates.
