# Client certificate authentication for policy delivery — unreleased v1.7 profile

This extension configures an explicit client certificate and private key for
the existing [HTTPS policy synchronization command](CHECKPOINT_POLICY_DELIVERY_V1.7.md).
It enables connections to organizational endpoints that require mutual TLS
(mTLS). It is implemented in development and is absent from published v1.7.0
assets. It does not deploy a publisher, issue credentials, schedule updates, or
contact an endpoint during case verification.

## Separate trust decisions

The verifier authenticates the HTTPS server using its existing hostname and CA
checks. The publisher can authenticate the connecting verifier using a separate
client certificate. Python's
[TLS documentation](https://docs.python.org/3/library/ssl.html) describes loading
client credentials with `SSLContext.load_cert_chain()` and requiring certificates
on the server with `CERT_REQUIRED`.

Transport identity grants no checkpoint-policy authority. After receiving a
response, the verifier still authenticates the complete issuer-root chain and
policy quorum against its independent anchor, checks validity and revision
floors, and activates accepted state atomically. Invalid signatures, wrong scope,
rollback attempts, or failed transport leave the governed store unchanged.

Client configuration also does not prove that a server required, received, or
authorized that certificate. A server that never requests a client certificate
can return a successful response. The receipt reports the configured identity
and deliberately leaves `peer_client_authentication_proven` false. Server-side
access controls and independently retained audit records establish that boundary.

## Credential profile

All identity inputs are explicit local paths; nothing reads a client identity
from the URL, case package, policy bundle, or environment. Certificate and key
paths are required together. A password file or certificate pin supplied alone
also fails before DNS or HTTP is attempted.

| Input | Contract |
| --- | --- |
| Certificate chain | PEM certificates only, leaf first, at most 256 KiB and 16 certificates; no duplicates or extra material |
| Leaf certificate | Current at system UTC; non-CA Basic Constraints, digital-signature Key Usage, and Extended Key Usage restricted to TLS client authentication |
| Certificate public keys | RSA of at least 2048 bits, EC P-256/P-384/P-521, Ed25519, or Ed448 |
| Certificate signature digest | SHA-256/SHA-384/SHA-512, or the intrinsic digest of an EdDSA signature |
| Private key | One matching PKCS8 PEM key, encrypted or unencrypted, at most 64 KiB; traditional OpenSSL key formats are rejected |
| Password file | At most 4096 bytes including an optional trailing LF/CRLF; one nonempty line with no interior CR/LF or NUL; used for an encrypted key |
| Optional pin | Independently retained lowercase 64-character SHA-256 of the leaf certificate's DER bytes |

The leaf validity check uses the
[cryptography X.509 UTC properties](https://cryptography.io/en/latest/x509/reference/).
Private-key decoding and matching use its
[serialization API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/).
The publisher remains responsible for validating the complete client certificate
chain and determining which authenticated identities may read which policy.
Local chain parsing is not a substitute for that server-side validation.

Files must be regular, non-symlink files. On POSIX, key and password files must
be owned by the current process user with no group or other permissions, such
as mode `0600` or `0400`. This deliberately rejects shared key files. On Windows,
provision equivalent access restrictions through the organization's ACL controls;
this profile does not independently validate Windows ACLs. For secret-manager
mounts or renewal systems that expose symlinks, materialize protected regular
files through the approved provisioning process.

The loader validates bounded snapshots of the certificate, key, and password.
It passes those exact certificate/key bytes through a private temporary directory
because OpenSSL's certificate-loading API takes filenames. Temporary files use
mode `0600`, and the directory is removed on success or failure. Encrypted keys
remain encrypted in the temporary file. Passwords are supplied through a callback
so an unattended command never falls back to OpenSSL's interactive password
prompt. Python does not guarantee zeroization of credential bytes in memory.

Delivery disables TLS key logging before connecting, including when
`SSLKEYLOGFILE` is present. The standard context factory may create that file's
header, but no TLS session secrets are written by this delivery connection.
Credential contents, private paths, and backend exception details are excluded
from delivery receipts and credential error messages.

## Synchronize with an approved client identity

Provision credentials through the organization's existing PKI and secret-delivery
process. Keep TLS credentials separate from checkpoint signing and policy issuer
keys. Supply your own endpoint, filenames, and independently obtained digests:

```bash
python checkpoint_delivery_v17.py sync \
  --store approved-policy.sqlite --anchor approved-root.json \
  --url https://policy.example.org/policy.json \
  --ca-file approved-server-ca.pem \
  --client-cert-file verifier-client-chain.pem \
  --client-key-file verifier-client-key.pem \
  --client-key-password-file verifier-key-password.txt \
  --expected-client-certificate-sha256 APPROVED_CLIENT_DER_SHA256 \
  --minimum-policy-revision 2 --minimum-root-version 2
```

The uppercase digest is a placeholder for a real lowercase SHA-256 value.
Omit the password-file option for an unencrypted PKCS8 key. Never put a password
or private key directly in the command line. Paths select local files, not
commands to execute or remote credential sources.

The Python API adds `client_cert_file`, `client_key_file`,
`client_key_password_file`, and `expected_client_certificate_sha256` keyword
arguments to `sync_policy()`. Existing calls without identity options retain
ordinary HTTPS behavior. Each invocation creates a fresh TLS context; credential
rotation takes effect on the next invocation. Update an independently retained
leaf pin through the approved process when rotating certificates. There is no
automatic retry using an older identity or a connection without a certificate.

No redirect is followed, including one from an authenticated publisher. Existing
proxy-environment isolation, one-response framing, bounded downloads, timeout,
and response-deadline rules remain in force. The endpoint URL is explicit
operator configuration; approve it before sending a client certificate.

## Publisher and operational requirements

Use the organization's approved TLS gateway or publisher to require a valid
client certificate at the initial handshake. An optional-certificate setting
does not enforce this requirement. Configure a dedicated client CA or explicit
authorization rules that limit each machine identity to its intended policy
scope. A broadly shared corporate CA alone may authorize too many clients.

Provision server identity and approved CA trust independently on each side.
Keep signing/issuer private keys out of the delivery service: it serves already
approved bundles created by the existing bundle command. Disable public fallback
routes and use publisher audit records to record the authenticated identity and
policy response. Certificate issuance, revocation, renewal, gateway hardening,
availability, and schedule approval/supervision remain operator responsibilities.
The separate [scheduling profile](POLICY_SYNC_SCHEDULING_V1.7.md) can execute
approved recurring jobs and reloads these credential files before each attempt.
This profile adds no CRL/OCSP fetching, hardware-backed key integration, or
organization-wide identity inventory. Case verification stays offline and uses
the latest locally accepted policy rather than contacting the publisher.

## Results and failure behavior

Successful delivery adds `delivery.client_identity` with schema
`ai-dfir/policy-delivery-client-identity/v1.7`:

| Field | Meaning |
| --- | --- |
| `status` | CONFIGURED when validated credentials were loaded; NOT_CONFIGURED when all identity options are absent |
| `certificate_sha256` | Configured leaf DER digest |
| `certificate_chain_sha256`, `certificate_count` | Exact loaded PEM chain and count |
| `not_valid_before`, `not_valid_after` | Configured leaf's UTC validity interval |
| `peer_client_authentication_proven` | Always false: client receipt alone does not prove publisher enforcement |
| `policy_authority_granted` | Always false: issuer authority is verified independently |

Credential validation failures use `delivery_identity_*` error codes and
`network_attempted: false`. Missing, mismatched, expired, weak, wrong-purpose,
overly accessible, malformed, or partially configured credentials fail closed.
TLS rejection may surface as `policy_delivery_tls` or `policy_delivery_network`
depending on how the peer closes the connection; both fail synchronization.
The CLI exits 0 for accepted/unchanged authenticated policy state, 1 for rejected
sync or identity configuration, 2 for argument syntax, and 3 for other local
setup errors. A successful TLS connection alone is never an accepted update.

## Acceptance

The synthetic self-test runs a temporary loopback TLS endpoint requiring client
certificates. It rejects an anonymous client, accepts an encrypted client key,
rejects a tampered issuer policy afterward, and verifies the case offline.
The 80 focused regressions add rejected/untrusted peers, strict local credential
preflight, secret-file permissions and bounds, malformed PEM rejection within a
subprocess deadline, snapshot cleanup, no secret logging,
server trust, redirects, policy gates, credential rotation inputs, and CLI behavior.

The source and extracted full release gates require this profile's files and
results. It reuses the existing standard library and cryptography dependency;
no new runtime dependency or service is installed. Published v1.7.0 packages
retain their original verification contract.
