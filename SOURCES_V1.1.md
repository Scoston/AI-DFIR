# AI-DFIR v1.1 Standards and Attack-Surface Sources

Verified 2026-08-23.

## Agent harness

Cloudflare Agents — Harnesses
https://developers.cloudflare.com/agents/harnesses/

A harness is the turn-by-turn loop around the model responsible for prompt
construction, memory, tools/tool results, response handling and continue/stop
behavior. v1.1 therefore treats the harness as a first-class forensic object.

## A2A v1.0

A2A Protocol — Announcing Version 1.0
https://a2a-protocol.org/latest/announcing-1.0/

A2A v1.0 is the stable production-ready Agent-to-Agent protocol release. It
includes enterprise features such as multi-tenancy and signed Agent Cards.

A2A Specification
https://a2a-protocol.org/latest/specification/

v1.1 captures Agent Cards, skills, supported interfaces, security schemes,
tasks, contexts and push-notification configuration.

## MCP 2026-07-28

Model Context Protocol — The 2026-07-28 Specification
https://blog.modelcontextprotocol.io/posts/2026-07-28/

Relevant forensic features:
- stateless protocol core
- Mcp-Method / Mcp-Name headers
- cacheable list results
- issuer-validation / authorization hardening
- Tasks extension
- formal extensions framework

## NIST agent tool use / computer use

NIST — Lessons Learned from the Consortium: Tool Use in Agent Systems
https://www.nist.gov/news-events/news/2025/08/lessons-learned-consortium-tool-use-agent-systems

NIST distinguishes read-only, constrained-write and write agents and explicitly
includes browser/computer use, code execution, software extensions and
agent-to-agent interaction in the agent tool surface.

NIST CAISI — Insights into AI Agent Security from a Large-Scale Red-Teaming Competition
https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition

The work highlights indirect prompt injection / agent hijacking risks when
agents ingest content from external sources such as email, websites and code repositories.

## Browser session hijacking example

NVD CVE-2026-40289
https://nvd.nist.gov/vuln/detail/CVE-2026-40289

A multi-agent browser bridge could permit unauthenticated remote browser-session
hijacking through a WebSocket control path, motivating preservation of browser
bridge identity/origin/WebSocket evidence.
