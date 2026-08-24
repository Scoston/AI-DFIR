# MCP Investigation Guide

For MCP 2026-07-28 preserve:

- server identity/transport;
- `Mcp-Method` and `Mcp-Name`;
- tool/resource/prompt catalog and cache state;
- tool schema version/hash;
- OAuth issuer/client/PKCE/resource metadata;
- Tasks lifecycle and cancellation;
- extension negotiation;
- multi-round-trip/input-required exchanges;
- MCP App/UI resources and host actions;
- root/path resolution;
- arguments/results and target-system audit.

Tool name alone is not effective tool identity. Include server endpoint,
certificate/transport identity, schema hash, version, and authorization context.
