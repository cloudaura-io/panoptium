---
id: "F.4"
title: "Dependency Confusion in Agent Ecosystems"
category: "Supply Chain"
category_id: "F"
detection_difficulty: "medium"
description: "Traditional dependency confusion (exploiting how package managers
  resolve private vs. public packages) applied to AI agent tool ecosystems."
---

# F.4 Dependency Confusion in Agent Ecosystems

- **Name:** Dependency Confusion for AI Agents
- **Category:** Supply Chain / Dependencies
- **Description:** Traditional dependency confusion (exploiting how package managers
  resolve private vs. public packages) applied to AI agent tool ecosystems. Combined
  with slopsquatting, attackers can squat hallucinated names that happen to match
  real internal package names.
- **Attack scenario:** An organization uses an internal MCP server called
  "internal-auth-helper." An attacker publishes a public npm package with the same
  name. When an agent attempts to install dependencies, the public package is
  resolved instead of the internal one, executing the attacker's code.
- **Prerequisites:** Knowledge of internal package/tool names (sometimes guessable),
  ability to publish public packages.
- **Impact:** Code execution within the agent's environment, credential theft,
  persistent access.
- **Detection difficulty:** Medium. Package source verification and pinning can
  mitigate, but requires explicit configuration.
- **References:**
  - Andrew Nesbitt: "Slopsquatting meets Dependency Confusion"
