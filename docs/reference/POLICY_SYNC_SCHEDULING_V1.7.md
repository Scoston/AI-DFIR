# Controlled policy synchronization scheduling

This development profile is implemented but unreleased and is not included in
published v1.7.0 assets. It executes approved jobs through the existing
[HTTPS delivery](CHECKPOINT_POLICY_DELIVERY_V1.7.md) and optional
[mTLS client identity](POLICY_DELIVERY_MTLS_V1.7.md) profiles.

## Authority and deployment boundary

An operator defines each job's existing governed store, independently provisioned
root anchor and canonical SHA-256 pin, HTTPS endpoint, transport credentials,
minimum revisions, and timing. Downloaded policy cannot change the schedule,
introduce trust anchors, initialize stores, or request arbitrary commands. Every
attempt authenticates the existing store and final candidate through the same
quorum, sequential root-chain, current-validity, rollback, and recovery-floor
checks as an explicit delivery command. Each accepted store update is atomic.

Scheduling grants no new checkpoint authority and makes no global-latest claim.
Case export, verification, and replay remain offline and apply their own current
policy gates. A scheduler outage does not extend a policy's validity window.
Operators supply the publisher, credentials, protected directories, service
account, process supervisor, and monitoring. This profile installs no service.

## Approved configuration

Use an operator-owned UTF-8 JSON file with exactly `schema` and `jobs`. The raw
file and normalized snapshot are each limited to 128 KiB; there must be 1–32
jobs. Duplicate JSON keys, non-finite numbers, unknown fields, inline passwords,
and command hooks are rejected. Every job is validated before execution starts.
Disabled jobs must still have valid configuration and distinct identities/stores.

Example `schedule.json` below uses illustrative pins. Replace them with the
independently approved digests for your actual inputs before running it:

```json
{
  "schema": "ai-dfir/policy-sync-schedule/v1.7",
  "jobs": [
    {
      "job_id": "tenant-a-verifier",
      "store": "state/approved-policy.sqlite",
      "anchor": "trust/approved-root.json",
      "anchor_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "url": "https://policy.example.org/tenant-a/policy.json",
      "ca_file": "trust/publisher-ca.pem",
      "client_cert_file": "identity/client-chain.pem",
      "client_key_file": "identity/client-key.pem",
      "client_key_password_file": "identity/key-password.txt",
      "expected_client_certificate_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "minimum_policy_revision": 12,
      "minimum_root_version": 3,
      "enabled": true,
      "interval_seconds": 300,
      "max_backoff_seconds": 3600,
      "jitter_seconds": 30,
      "timeout_seconds": 10
    }
  ]
}
```

`anchor_sha256` hashes the validated root's RFC 8785 canonical JSON, not the raw
file formatting. From the repository directory, calculate a candidate digest:

```bash
python -c 'from v17_integrity import sha256_object; from v17_policy_governance import load_root; print(sha256_object(load_root("trust/approved-root.json")))'
```

Compare that candidate with independently approved root identity before putting
it in the schedule. Computing a digest from an untrusted download cannot approve
the anchor. The configured anchor remains the starting root as signed successor
roots rotate in the store; do not automatically replace its pin after updates.

| Field | Contract |
| --- | --- |
| `job_id` | Required, unique, 1–64 ASCII letters/digits/`.`/`_`/`-`, beginning with a letter or digit |
| `store`, `anchor` | Required local paths; store must already be initialized under the approved anchor |
| `anchor_sha256` | Required lowercase 64-digit canonical root SHA-256 |
| `url` | Required explicit ASCII HTTPS URL; existing delivery restrictions prohibit credentials, query, fragment, and redirects |
| `enabled` | Boolean, default `true`; disabled jobs perform no synchronization or credential/anchor preflight |
| `interval_seconds` | Integer 30–86400, default 300 |
| `max_backoff_seconds` | Integer from the interval through 604800, default the larger of 3600 and the interval |
| `jitter_seconds` | Integer 0 through the interval, default the smaller of 30 and the interval |
| `timeout_seconds` | Finite number 0.1–60, default 10; existing transport connection/response limits apply |
| `minimum_policy_revision`, `minimum_root_version` | Optional positive integers through 2^53−1; independent floors applied to the final candidate |
| `ca_file` | Optional approved server CA file; omission uses system TLS trust |
| `client_cert_file`, `client_key_file` | Optional together, using the existing protected mTLS credential profile |
| `client_key_password_file` | Optional protected file for an encrypted client key; requires certificate and key |
| `expected_client_certificate_sha256` | Optional independent lowercase leaf-certificate pin; requires certificate and key |

Paths are resolved relative to the configuration file's directory, irrespective
of the process working directory. There is no environment-variable or tilde
expansion. Paths cannot be empty, padded with whitespace, contain controls, or
exceed 4096 characters. Duplicate store paths, resolved aliases, and existing
hard-link aliases are rejected within one configuration.

The configuration must be a regular file, with no final symlink. On POSIX, its
owner must be root or the executing user, and group/other write access is
rejected; mode `0600` is appropriate. Protect its parent directories and every
trust, store, and credential path against unauthorized replacement. On Windows,
operators must enforce equivalent ACL protection. The mTLS profile separately
enforces its stricter private-key/password-file requirements.

## Check, run once, or supervise recurring work

```bash
python checkpoint_sync_v17.py check --config /approved/config/schedule.json
python checkpoint_sync_v17.py once --config /approved/config/schedule.json
python checkpoint_sync_v17.py watch --config /approved/config/schedule.json
```

`check` authenticates each enabled job's local store, compares the independent
anchor pin, and validates CA/client identity inputs without DNS or HTTP. A
`CHECKED` row reports `local_store_authenticated: true` and
`store_freshness_evaluated: false`: an expired but authentic store is permitted
for recovery. This does not test publisher reachability, publisher enforcement,
the current policy's eligibility for case use, or the existence of a new update.

`once` tries every enabled job once in configuration order. A missing anchor,
bad credential, failed transport, or rejected policy is reported for that job;
other valid jobs are still attempted. Results are not a fleet-wide transaction.
One failed job does not roll back an update accepted by another store.

`watch` tries enabled jobs immediately, emits each attempt as one flushed JSON
line before moving to the next job, then waits until a job is due. Use
`--max-rounds 1` for a finite supervised round; the optional bound is 1–1000000.
`--max-rounds` counts scheduling rounds, not attempts across all jobs. With every
job disabled, no attempt is made and watch exits cleanly.

On SIGINT/SIGTERM, idle waiting ends promptly. An in-flight synchronization is
allowed to finish its existing acceptance transaction; no subsequent job starts
after the stop request. This is graceful shutdown, not forced cancellation of
an active TLS/DNS operation. A supervisor may impose its own shutdown deadline.

## Timing, retries, and restart semantics

Deadlines use Python's [monotonic clock](https://docs.python.org/3/library/time.html#time.monotonic)
and begin when the preceding attempt completes. UTC timestamps are diagnostic
wall-clock observations, not trusted timestamp receipts. Changing UTC cannot
advance a monotonic retry deadline; certificate and policy validity still depend
on the existing system UTC checks.

After success the next delay is the interval plus randomly selected integer
jitter from zero through `jitter_seconds`. Failures use interval × 1, 2, 4, 8,
and so on, plus jitter. The final delay is capped by `max_backoff_seconds`.
`ACCEPTED` or `UNCHANGED` resets backoff. With interval 30, cap 120, and no jitter,
consecutive failures schedule retries in 30, 60, 120, 120 seconds.

Jobs run sequentially, once per due round, with no catch-up burst after missed
intervals. A slow job can delay later jobs. Existing connection and response
limits apply; DNS resolution is not independently bounded by a total fleet
deadline. An instance rejects overlapping `run_due()` rounds. There is no
cross-process lock, leader election, or distributed fairness guarantee.

Timing, attempt counts, and failure counts are process-local. The reported
consecutive failure count saturates at 20 after backoff is already capped.
Restarting makes every enabled job immediately due and resets those counters;
it does not reset accepted root/policy history in governed stores. Run one
supervised scheduler instance per configuration and avoid overlapping external
`once` invocations. The existing store transactions and chain/floor checks remain
the authority boundary if another authorized updater runs concurrently.

The configuration is snapshotted at startup. Editing it requires an explicit
restart/reload by the operator; downloaded metadata cannot hot-reload it. Anchor,
CA, certificate, key, and password files are read again on each attempt. Changed
anchor bytes must still match the retained approved pin. Client-certificate
rotation must respect any retained leaf pin. Invalid replacement credentials
fail before network use and cannot trigger anonymous fallback.

## Reports and failure interpretation

`check` and `once` produce `ai-dfir/policy-sync-run/v1.7` reports. Overall status
is `FAIL` if any enabled job fails, otherwise `PASS`; disabled jobs are identified.
A watch attempt uses `ai-dfir/policy-sync-attempt/v1.7` and reports job ID,
normalized configuration digest, local UTC start/finish, status, whether network
was attempted, attempt/failure counts, and the next delay. Successful attempts
include the existing transport receipt and independent policy authentication
report. Preserve those records according to the organization's audit policy.

Failed attempts include a stable error code with no private key, password,
raw configuration, credential path, or backend exception text. Successful
delivery receipts retain their existing endpoint and public identity metadata.
The normalized configuration digest identifies the approved settings including
absolute paths; it is not a signature, content archive, or authorization proof.

On graceful watch exit, the final report is `STOPPED` with
`scheduling_state_persisted: false`. It does not assert successful delivery:
monitor individual attempt statuses and policy validity. `check`/`once` exit 0
for `PASS` and 1 for `FAIL`; watch exits 0 for a clean stop even if attempts
failed. Invalid configuration/execution inputs exit 1 and argparse usage errors
exit 2. Output failure stops further jobs; an already committed store update
cannot be undone simply because its report could not be written.

The scheduler does not retain logs, install alerts, start an external publisher,
issue credentials, or provide durable retry scheduling/HA coordination.

## Acceptance evidence

The synthetic acceptance case uses encrypted mTLS credentials and a loopback
publisher: offline preflight, authenticated activation, tampered-policy rejection,
backoff, recovery, and subsequent offline case verification. The 85 focused
regressions cover timing, strict inputs, independent authority/floors, per-job
failure handling, replacement credentials, process restarts, overlapping rounds,
output/shutdown behavior, and the CLI. Source and extracted-package release
gates both require this profile. See [Testing](../../TESTING.md).
