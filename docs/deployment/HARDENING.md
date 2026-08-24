# Deployment Hardening

- run services as non-root;
- use read-only provider scopes;
- separate response, approval, evidence, collector, and release signing keys;
- keep private keys in KMS/HSM/secret stores;
- restrict Workbench exposure to authenticated internal paths;
- allowlist collector types; never accept arbitrary shell payloads;
- restrict parser/analysis egress;
- do not automatically fetch untrusted `jku`, fonts, or document resources;
- monitor RLS failures, KMS use, retention changes, collector enrollment, and
  gateway authentication failures;
- use protected branches, code review, dependency review, CodeQL, secret
  scanning, and OpenSSF Scorecard for the public repository.
