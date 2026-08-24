# v0.9 Standards / Threat-Framework Sources

Verified 2026-08-23.

## OWASP Agentic Top 10 2026
https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Categories used:
- ASI01 Agent Goal Hijack
- ASI02 Tool Misuse & Exploitation
- ASI03 Identity & Privilege Abuse
- ASI04 Agentic Supply Chain Vulnerabilities
- ASI05 Unexpected Code Execution (RCE)
- ASI06 Memory & Context Poisoning
- ASI07 Insecure Inter-Agent Communication
- ASI08 Cascading Failures
- ASI09 Human-Agent Trust Exploitation
- ASI10 Rogue Agents

## MITRE ATLAS
https://atlas.mitre.org/

The public matrix observed on 2026-08-23 showed:
- 16 tactics
- 178 techniques
- agentic-AI platform coverage
- techniques including AI Agent Tool Invocation, AI Agent Context Poisoning,
  AI Agent Tool Data Poisoning, AI Agent Tool Poisoning, Deploy AI Agent,
  Exfiltration via AI Agent Tool Invocation and others.

## MCP 2026-07-28
https://blog.modelcontextprotocol.io/posts/2026-07-28/

Relevant forensic changes:
- stateless protocol core
- Mcp-Method / Mcp-Name header routing
- cacheable tools/prompts/resources list results
- authorization hardening
- issuer validation
- Tasks extension
- extension framework
- formal deprecation policy
