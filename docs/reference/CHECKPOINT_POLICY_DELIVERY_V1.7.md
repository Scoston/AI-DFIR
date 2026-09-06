# Online checkpoint-policy and issuer-root delivery

This development profile is implemented but unreleased; it is not part of the
published v1.7.0 assets. It adds an explicit HTTPS synchronization command to
[signed issuer governance](CHECKPOINT_POLICY_GOVERNANCE_V1.7.md). It supplies a
client and publisher bundle format, not an operated distribution service.

## What a successful synchronization establishes

The client received one bounded response over certificate- and hostname-verified
TLS. It authenticated the complete issuer-root chain from the independently
supplied anchor, preserved the store's accepted chain prefix, verified the final
policy against the resulting issuer quorum, and atomically activated the final
current root/policy. Both the previous and replacement quorums must approve
every root transition. A higher policy revision is required when a root changes.

Transport and authority are separate checks. A valid TLS certificate does not
authorize policy changes. A downloaded document cannot supply an anchor, a new
endpoint, issuer trust outside the signed chain, or independent recovery floors.
The endpoint can withhold updates or replay still-current metadata; success does
not prove that the received policy is globally latest. Current-root/policy expiry
and externally retained version floors remain necessary.

Case verification, export, and replay do not contact the endpoint. They consume
the previously authenticated local store and recheck its authority, signatures,
current validity, and configured minimum versions offline.

## Trust and deployment inputs

Provision the root anchor independently using the governance procedure. Protect
the anchor, governed SQLite store, TLS CA configuration, command arguments, and
independent minimum policy/root versions. The client requires an existing format
2 governed store. It does not initialize, migrate, re-anchor, or reset it from a
network response. Use the existing offline initialization or explicit migration
commands first.

The HTTPS URL must be operator configuration. Do not derive it from case content,
an agent/tool response, or other untrusted evidence. An explicit internal or
loopback endpoint is allowed; this CLI is not an SSRF filter for an application
that accepts arbitrary user URLs. The client never follows redirects or metadata
links. It sends one GET with fixed public request headers and no request body,
case evidence, credentials, cookies, or policy revisions.

System TLS trust is used by default. `--ca-file` instead supplies an independently
provisioned PEM CA bundle, bounded to 1 MiB. TLS 1.2 or later, certificate checks,
and hostname checks are mandatory. There is no insecure TLS switch. Proxy
environment variables and netrc credentials are not used. HTTP authentication,
client certificates, and explicit proxy support are outside this profile.
Operators must choose a publication endpoint whose network access and metadata
confidentiality are appropriate for its audience; this client authenticates the
server but does not authenticate itself to it.

## Publisher bundle

The JSON object has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | `ai-dfir/checkpoint-policy-delivery/v1.7` |
| `rotations` | Complete ordered signed root-rotation chain starting at the independent anchor; empty before the first rotation |
| `signed_policy` | Final quorum-signed checkpoint policy under the resulting root |

The wrapper is not a new signature scheme. Each existing rotation carries its
two role-bound quorums, and the final policy carries its issuer quorum bound to
that issuer configuration. Canonical bundle hashing is receipt metadata; the
authority claim comes from those signatures and the independent anchor.

Prepare current signed policy and rotation files with the existing offline
policy/governance commands. Assemble a bundle without sharing private keys with
the publisher or delivery client:

```bash
python checkpoint_delivery_v17.py bundle \
  --anchor approved-root-v1.json \
  --rotation approved-root-v1-to-v2.json \
  --rotation approved-root-v2-to-v3.json \
  --signed-policy signed-policy-r12.json \
  --out policy-delivery.json
```

Repeat `--rotation` in order from the original anchor, including already
distributed rotations. Omit it for a policy issued directly under the anchor.
The command verifies all transitions and the final current root/policy before
writing canonical JSON. It refuses to overwrite an existing destination. It
does not accept the policy into any store or contact a service.

Publish this file at a stable, operator-approved HTTPS URL. Configure the server
to return status 200, a single `Content-Type: application/json` header (optional
`charset=utf-8`), and a single correct `Content-Length`. Serve the complete body
without compression, chunked transfer, partial ranges, or redirects. Update the
published object atomically so a client receives a complete old or new bundle.
Retain previous signed rotation objects exactly, including their approval sets.

## Explicit synchronization

```bash
python checkpoint_delivery_v17.py sync \
  --store verifier-policy.sqlite \
  --anchor approved-root-v1.json \
  --url https://updates.example.org/tenant-a/policy-delivery.json \
  --ca-file independently-approved-delivery-ca.pem \
  --minimum-policy-revision 12 \
  --minimum-root-version 3 \
  --timeout 10
```

Omit `--ca-file` to use system TLS trust. Minimum versions are optional, but must
come from an independent source when used for backup recovery. They constrain
the final candidate under the transaction lock, so recovery from an older valid
store can advance directly to an acceptable state. A successful update does not
itself persist these external minimum requirements outside the database.

The URL must be an ASCII HTTPS URL of at most 2,048 characters, with a valid
hostname/IP and optional port. Credentials, query strings, fragments, raw
whitespace/control characters, malformed percent escapes, encoded controls,
scoped IPv6 addresses, and ambiguous host forms are rejected before networking.
Use an ASCII IDNA hostname if needed. No metadata field can override the URL.

The connection timeout defaults to 10 seconds and accepts 0.1 through 60 seconds.
It applies to socket/TLS operations; platform DNS resolution and multiple address
attempts are not a strict whole-command deadline. After TLS connects, a separate
deadline closes the transport if sending the request, receiving headers, or
reading the body takes longer than the configured interval, including a peer
that trickles bytes. Signature checks and the SQLite transaction are outside
the response deadline. There is no automatic retry or background polling.

The maximum raw response is 5,260,288 bytes: a 4 MiB chain allowance, a 1 MiB
policy plus 16 KiB signature allowance, and 1 KiB for the wrapper. Component
limits still apply independently, including at most 64 retained root rotations.
JSON rejects duplicate fields, non-finite numbers, malformed UTF-8, excessive
nesting, and unsupported fields. TLS, HTTP status/framing, timeout, truncation,
parsing, signature, freshness, floor, or transaction failure returns a failed
sync. It never reports successful synchronization from an old cached policy.

## Catch-up, retries, and recovery

Local preflight authenticates the existing store and supplied anchor before
contacting the endpoint. It permits an expired stored root or policy so recovery
can proceed, but rejects invalid signatures, mismatched anchors, missing stores,
or unsupported formats. The store is authenticated again under a write lock
after the download, so an intervening update cannot be overwritten silently.

The incoming full chain must be at least as long as the accepted chain, and its
prefix must match the retained signed rotations exactly after normalization.
An alternate quorum-approved fork cannot replace an accepted transition.
Additional signatures added to a past rotation change that retained object;
publishers must keep the already published approval set stable.

Multiple root transitions may be accepted together. Every transition is checked,
including transitions through expired intermediate roots. Only the final root
and final policy become active. Intermediate policies are neither installed nor
used to make historical authorization claims. The final root and policy must be
current according to the system UTC clock, and the final policy revision must
exceed the stored revision whenever the chain extends.

An exact bundle retry returns `UNCHANGED` and preserves acceptance times. A new,
higher policy revision with the same complete chain is allowed. Lower revisions,
changed policies at the same revision, and lower/conflicting chains fail. Root,
retained chain, and policy writes commit together; readers cannot see a partially
activated pair. Concurrent conflicting deliveries produce one accepted state
and a rejected conflict.

Independent floors detect whole-database restoration only when the restored or
delivered state is below the corresponding floor. Protect and retain both floors
outside the backup. They are not hardware monotonic counters. Chain limits still
require the independently approved recovery process described in governance;
delivery cannot truncate the history or authorize a new anchor.

## Reports and API

`sync` writes JSON to standard output using
`ai-dfir/checkpoint-policy-delivery-report/v1.7`. Status is `ACCEPTED` or
`UNCHANGED`. Its `delivery` object records the configured URL, raw response and
canonical bundle SHA-256 digests, byte count, receipt time, peer certificate hash,
TLS version, configured CA hash/trust source, timeout/deadline, and one HTTP
request with zero redirects. Receipt time is local audit metadata, not trusted
timestamp evidence. HTTP Date/Last-Modified/ETag values grant no authority.

The separate `authentication` object is the existing governed-policy report,
including root/anchor/chain identities, current policy revision, and quorum
results. It correctly reports `network_performed: false` for the signature/store
authentication itself. The outer delivery report records `network_performed:
true`, `latest_available_proven: false`, and `historical_delivery_time_proven:
false`. Retain stdout through the operator's normal audit process. The database
retains canonical signed roots, approvals, and current policy; it does not retain
raw HTTP responses or a transport-receipt history.

Failures expose a machine-readable `code` and `network_attempted` without
returning an untrusted response body. The CLI exits 0 for successful preparation
or sync, 1 for rejected delivery/authority/state, 2 for argument errors, and 3 for
local file/configuration errors outside synchronization. A failed sync changes
no root or policy through its transaction; another concurrent authorized updater
may independently advance the store. Case verification can separately use the
last accepted policy only while its own current-validity requirements hold.

Python APIs are `prepare_delivery_bundle`, `validate_delivery_bundle`, and
`sync_policy` in `v17_policy_delivery.py`; atomic activation uses
`accept_governed_chain` in `v17_policy_governance.py`. Structural bundle validation
alone does not authenticate its signatures. None of these functions grants
historical authorization, custodian independence, protection from quorum key
compromise, or a deployment certification.

## Acceptance and implementation references

The self-test uses a temporary loopback TLS server, synthetic CA, and ephemeral
keys. It accepts a signed rotation, rejects a corrupted download without changing
state, and verifies the case afterward with networking blocked. The 139 new
regression tests cover transport failures, strict framing/parsing, signed-chain
catch-up, expired-state recovery, conflicts/floors, atomic write failure,
concurrency, CLI workflows, and offline composition. The full release gate now
runs 570 v1.7 tests alongside 111 Evidence Packs and historical compatibility.
Packaging repeats the gate from extracted committed source and requires delivery
files and passing assurance; earlier published releases keep their old contract.

No dependencies were added. The implementation uses Python's
[HTTPS client](https://docs.python.org/3/library/http.client.html),
[TLS context](https://docs.python.org/3/library/ssl.html), and explicitly validated
[URL parsing](https://docs.python.org/3/library/urllib.parse.html#url-parsing-security),
plus the existing Ed25519/RFC8785 and SQLite governance code. Those libraries
provide transport primitives; the application enforces the delivery restrictions
and independent authority checks described above.
