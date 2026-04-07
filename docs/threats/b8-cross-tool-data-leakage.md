---
id: "B.8"
title: "Cross-Tool Data Leakage"
category: "Tool & MCP Attacks"
category_id: "B"
detection_difficulty: "hard"
description: "Sensitive data accessed through one tool is inadvertently or
  deliberately leaked to another tool. In MCP environments with multiple connected
  servers, credentials and data from one server can be passed to another through the
  agent's unified context window."
---

# B.8 Cross-Tool Data Leakage

- **Name:** Cross-Tool Data Leakage
- **Category:** Tool & MCP / Data Flow
- **Description:** Sensitive data accessed through one tool is inadvertently or
  deliberately leaked to another tool. In MCP environments with multiple connected
  servers, credentials and data from one server can be passed to another through the
  agent's unified context window. The agent does not enforce data compartmentalization
  between tools.
- **Attack scenario:** An agent connects to both a "database_query" MCP server
  (which requires authentication) and a "web_search" MCP server. The web_search
  server's tool description instructs the agent to include any available
  authentication tokens as search parameters, effectively exfiltrating the
  database credentials through search queries.
- **Prerequisites:** Agent connected to multiple tools/MCP servers, at least one
  of which is malicious or compromised.
- **Impact:** Credential leakage, data exfiltration across trust boundaries.
- **Detection difficulty:** Hard. Data flows through the agent's context window,
  which is not typically subject to data flow analysis.
- **References:**
  - Checkmarx: "11 Emerging AI Security Risks with MCP"
  - OWASP MCP06: Context Over-Sharing

---
