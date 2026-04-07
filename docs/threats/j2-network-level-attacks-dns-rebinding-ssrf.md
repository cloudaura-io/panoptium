---
id: "J.2"
title: "Network-Level Attacks (DNS Rebinding, SSRF)"
category: "Infrastructure"
category_id: "J"
detection_difficulty: "medium"
description: "DNS rebinding attacks resolve a domain to a benign address during
  validation but switch to an internal address at execution time, bypassing network
  security controls. SSRF attacks exploit agent HTTP capabilities to access internal
  services."
---

# J.2 Network-Level Attacks (DNS Rebinding, SSRF)

- **Name:** DNS Rebinding and SSRF Against Agent Infrastructure
- **Category:** Infrastructure / Network
- **Description:** DNS rebinding attacks resolve a domain to a benign address during
  validation but switch to an internal address at execution time, bypassing network
  security controls. SSRF attacks exploit agent HTTP capabilities to access internal
  services. Particularly dangerous for MCP servers running on localhost with SSE
  transport.
- **Attack scenario:** An attacker hosts a domain that resolves to their IP during
  the agent's initial connection check but then re-resolves to 127.0.0.1 or an
  internal Kubernetes service IP. The agent's subsequent requests reach internal
  services that should not be externally accessible.
- **Prerequisites:** Agent with HTTP capabilities, MCP servers running on localhost
  or internal network, ability to control DNS resolution.
- **Impact:** Access to internal services, MCP server compromise, credential theft
  from metadata services (IMDS).
- **Real-world examples:**
  - Straiker: "Agentic Danger: DNS Rebinding Exposes Internal MCP Servers"
  - AutoGPT SSRF bypass (GHSA-wvjg-9879-3m7w): all SSRF protection was
    bypassable.
- **References:**
  - Straiker AI Research blog
  - AutoGPT security advisory
