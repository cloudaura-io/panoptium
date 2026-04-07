---
id: "F.1"
title: "Poisoned MCP Servers and Tools"
category: "Supply Chain"
category_id: "F"
detection_difficulty: "hard"
description: "Attackers publish MCP servers containing tool poisoning payloads
  through package registries (npm, pip), marketplaces, or GitHub. Community plugin
  marketplaces have minimal vetting, allowing anyone to publish a \"useful\" tool
  with hidden data exfiltration, credential theft, or backdoor capabi..."
---

# F.1 Poisoned MCP Servers and Tools

- **Name:** Malicious MCP Server Distribution
- **Category:** Supply Chain / Tools
- **Description:** Attackers publish MCP servers containing tool poisoning payloads
  through package registries (npm, pip), marketplaces, or GitHub. Community plugin
  marketplaces have minimal vetting, allowing anyone to publish a "useful" tool
  with hidden data exfiltration, credential theft, or backdoor capabilities.
- **Attack scenario:** An attacker publishes an MCP server called "postgres-helper"
  on npm. It provides legitimate database query functionality but embeds hidden
  instructions in its tool descriptions that exfiltrate query results to an
  external server. Developers install it, and their agents begin silently leaking
  database contents.
- **Prerequisites:** Ability to publish to package registries or marketplaces.
- **Impact:** Compromise of all agents using the poisoned tool. Potential for
  widespread impact if the tool becomes popular.
- **Detection difficulty:** Hard. The tool provides legitimate functionality, making
  the poisoning hard to distinguish from normal behavior.
- **Real-world examples:**
  - September 2025: "postmark-mcp" npm package silently BCC'd all emails for weeks.
  - Over 70% of AI agent deployments use at least one unverified third-party plugin
    or community model.
  - MITRE ATLAS v5.4.0 added "Publish Poisoned AI Agent Tool" as a technique.
- **References:**
  - OWASP ASI04: Agentic Supply Chain Vulnerabilities
  - OWASP MCP04: Software Supply Chain Attacks
  - MITRE ATLAS: Publish Poisoned AI Agent Tool
