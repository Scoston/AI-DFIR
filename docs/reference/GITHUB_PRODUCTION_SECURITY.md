# GitHub Production Security

Recommended repository settings for a production AI-DFIR project:

- protect `main`; require pull requests, CODEOWNERS and at least two approvals for trust-boundary code;
- require CI, CodeQL, dependency review, Scorecard and full regression before release;
- disable force-push and branch deletion on protected release branches;
- require signed tags/releases where organization policy permits;
- enable secret scanning, push protection, Dependabot alerts and dependency graph;
- restrict GitHub Actions to approved actions and pin external actions by immutable commit in high-assurance environments;
- require an environment approval for release/publish jobs;
- publish source checksums, SBOM and SLSA provenance;
- sign production container images and admit by digest only.

The provided workflows use current 2026 action majors and SLSA GitHub Generator v2.1.0. Organizations with stricter supply-chain policy should replace major tags with reviewed commit SHAs.
