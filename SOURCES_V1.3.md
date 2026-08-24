# AI-DFIR v1.3 A2A Sources

Verified 2026-08-24.

## A2A Protocol v1.0
https://a2a-protocol.org/latest/whats-new-v1/

v1.0 introduced formal Agent Card signing using RFC 8785 JCS and RFC 7515 JWS.

## A2A Protocol Specification
https://a2a-protocol.org/latest/specification/

Relevant sections:

```text
4.4.1 AgentCard
4.4.7 AgentCardSignature
8.4 Agent Card Signing
8.4.1 Canonicalization Requirements
8.4.2 Signature Format
8.4.3 Signature Verification
```

The specification requires exclusion of `signatures` from the signed content,
JCS canonicalization, and JWS verification. It advises verification of at least
one signature before trust, supports trusted key stores, and says expired or
revoked keys must not be used.

## Normative A2A Proto
https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto

Used to model:

```text
REQUIRED fields
proto `optional` presence semantics
required repeated Agent Card fields
optional capability booleans
AgentSkill fields
AgentInterface fields
```

## Official JavaScript SDK
https://github.com/a2aproject/a2a-js

The stable SDK exposes Agent Card signing/verification support. Its v1.0.1
changelog included a fix to ensure signing and verification canonicalize the
same payload.

## RFC 8785 Python implementation
https://pypi.org/project/rfc8785/

Listed as the preferred Python canonicalization dependency.

AI-DFIR also includes a Node.js JCS fallback and refuses to use ordinary
Python JSON serialization as a substitute for RFC 8785.

## A2A per-request identity discussion
https://github.com/a2aproject/A2A/issues/1742

Used only to reinforce a forensic limitation: standardized Agent Card JWS does
not itself establish a cryptographic signature on every A2A request body.
AI-DFIR therefore preserves request transport/authentication evidence separately.
